"use client";

/**
 * Email verification landing page.
 *
 * The backend emails `{APP_BASE_URL}/verify?token=…`
 * (platform/router.py request_email_verification), but this page did not exist,
 * so every verification link 404'd. Consumes the single-use token on mount.
 */

import { Suspense, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { ApiError, api } from "@/lib/api";
import { Brand } from "@/components/Brand";

type State = "working" | "ok" | "invalid" | "missing";

function VerifyEmailInner() {
  const params = useSearchParams();
  const token = params?.get("token") || "";
  const [state, setState] = useState<State>(token ? "working" : "missing");
  const [detail, setDetail] = useState<string | null>(null);
  // The token is SINGLE-USE — guard against React StrictMode's double-invoke in
  // dev, which would otherwise consume it once and then report "invalid".
  const consumed = useRef(false);

  useEffect(() => {
    if (!token || consumed.current) return;
    consumed.current = true;
    let cancelled = false;
    api
      .confirmEmailVerification(token)
      .then(() => !cancelled && setState("ok"))
      .catch((err) => {
        if (cancelled) return;
        setState("invalid");
        setDetail(err instanceof ApiError ? err.detail : null);
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  return (
    <div className="auth-shell stack" style={{ gap: 20 }}>
      <Brand size={26} />
      <section className="panel stack">
        {state === "working" && (
          <>
            <h3 style={{ marginTop: 0 }}>Verifying your email…</h3>
            <p className="muted" style={{ margin: 0 }}>
              One moment.
            </p>
          </>
        )}
        {state === "ok" && (
          <>
            <h3 style={{ marginTop: 0 }}>
              Email verified <span className="badge ok">done</span>
            </h3>
            <p className="muted" style={{ margin: 0 }}>
              Thanks — your address is confirmed.
            </p>
            <Link href="/dashboard">
              <button>Go to dashboard</button>
            </Link>
          </>
        )}
        {state === "invalid" && (
          <>
            <h3 style={{ marginTop: 0 }}>That link didn&apos;t work</h3>
            <p className="muted" style={{ margin: 0 }}>
              Verification links are single-use and expire. Request a fresh one
              from your dashboard.
              {detail ? ` (${detail})` : ""}
            </p>
            <Link href="/dashboard">
              <button className="ghost">Back to dashboard</button>
            </Link>
          </>
        )}
        {state === "missing" && (
          <>
            <h3 style={{ marginTop: 0 }}>Nothing to verify</h3>
            <p className="muted" style={{ margin: 0 }}>
              This page needs a verification link from your email.
            </p>
            <Link href="/dashboard" className="muted">
              ← Back to dashboard
            </Link>
          </>
        )}
      </section>
    </div>
  );
}

export default function VerifyEmailPage() {
  return (
    <Suspense
      fallback={
        <div className="auth-shell">
          <p className="muted">Loading…</p>
        </div>
      }
    >
      <VerifyEmailInner />
    </Suspense>
  );
}
