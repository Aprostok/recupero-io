"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth";
import { ApiError, Me, TraceSummary, api } from "@/lib/api";

// The tools grid — one card per product surface, so everything we've built is
// discoverable from the home.
const TOOLS: { href: string; label: string; desc: string }[] = [
  { href: "/dashboard/traces", label: "Traces", desc: "Start a recovery and view your cases" },
  { href: "/dashboard/guard", label: "Wallet Guard", desc: "Screen an address before you sign" },
  { href: "/dashboard/assistant", label: "Assistant", desc: "Ask questions about a case or address" },
  { href: "/dashboard/keys", label: "API Keys", desc: "Programmatic access to the API" },
  { href: "/dashboard/members", label: "Members", desc: "Invite and manage your team" },
  { href: "/dashboard/activity", label: "Activity", desc: "Security audit log for your org" },
  { href: "/dashboard/billing", label: "Billing", desc: "Plan, usage, and what's unlocked" },
  { href: "/academy", label: "Academy", desc: "Learn to read a trace, mixer, or peel chain" },
];

function statusBadge(status: string) {
  const cls =
    status === "complete" ? "ok" : status === "failed" ? "warn" : "muted";
  return <span className={`badge ${cls}`}>{status}</span>;
}

export default function DashboardHome() {
  const { token } = useAuth();
  const [me, setMe] = useState<Me | null>(null);
  const [traces, setTraces] = useState<TraceSummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    api
      .me(token)
      .then((m) => !cancelled && setMe(m))
      .catch((err) => !cancelled && setError(err instanceof ApiError ? err.detail : "failed to load"));
    api
      .listTraces(token, 5)
      .then(({ traces }) => !cancelled && setTraces(traces))
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [token]);

  const usage = me?.usage;
  const used = usage?.traces_used ?? 0;
  const remaining = usage?.traces_remaining ?? 0;
  // included = used + remaining when metered; remaining < 0 means unlimited.
  const included = remaining < 0 ? -1 : used + remaining;
  const pct = included > 0 ? Math.min(100, (used / included) * 100) : 0;

  return (
    <div className="stack" style={{ gap: 24 }}>
      {/* Hero */}
      <section className="panel stack">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <div>
            <h2 style={{ margin: 0 }}>Welcome back</h2>
            <p className="muted" style={{ margin: "4px 0 0" }}>
              Trace stolen crypto, see where it&apos;s sitting now, and act on it.
            </p>
          </div>
          {me && (
            <span className="badge ok" style={{ textTransform: "capitalize" }}>
              {me.plan} plan
            </span>
          )}
        </div>
        <div className="row">
          <Link href="/dashboard/traces">
            <button>＋ Start a recovery</button>
          </Link>
          <Link href="/dashboard/guard" className="muted">
            or screen an address →
          </Link>
        </div>
      </section>

      {/* Quota */}
      <div className="hero-metrics">
        <div className="stat-tile">
          <div className="k">Traces this period</div>
          <div className="v">
            {used}
            {included >= 0 && (
              <span className="muted" style={{ fontSize: 14 }}> / {included}</span>
            )}
          </div>
        </div>
        <div className="stat-tile good">
          <div className="k">Remaining</div>
          <div className="v">{remaining < 0 ? "∞" : remaining}</div>
        </div>
        <div className="stat-tile">
          <div className="k">Rate limit</div>
          <div className="v">
            {usage?.rate_limit_per_min ?? "—"}
            <span className="muted" style={{ fontSize: 14 }}> /min</span>
          </div>
        </div>
      </div>
      {included > 0 && (
        <div className="recover-bar" aria-hidden>
          <div className="recover-seg good" style={{ width: `${pct}%` }} />
          <div
            className="recover-seg"
            style={{ width: `${100 - pct}%`, background: "rgba(255,255,255,.05)" }}
          />
        </div>
      )}

      {/* Recent traces */}
      <section className="panel stack">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <h3 style={{ margin: 0 }}>Recent traces</h3>
          <Link href="/dashboard/traces" className="muted">
            View all →
          </Link>
        </div>
        {traces.length === 0 ? (
          <p className="muted">
            No traces yet —{" "}
            <Link href="/dashboard/traces">start your first recovery</Link>.
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Case</th>
                <th>Chain</th>
                <th>Status</th>
                <th>Submitted</th>
              </tr>
            </thead>
            <tbody>
              {traces.map((t) => (
                <tr key={t.investigation_id}>
                  <td>
                    <Link href={`/dashboard/traces/${t.investigation_id}`}>
                      {t.case_id || `${t.investigation_id.slice(0, 8)}…`}
                    </Link>
                  </td>
                  <td>{t.chain}</td>
                  <td>{statusBadge(t.status)}</td>
                  <td className="muted">
                    {t.created_at ? new Date(t.created_at).toLocaleString() : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {/* Tools */}
      <section className="stack">
        <h3 style={{ margin: "0 0 4px" }}>Everything in one place</h3>
        <div className="tool-grid">
          {TOOLS.map((t) => (
            <Link key={t.href} href={t.href} className="tool-card">
              <div className="tool-label">{t.label}</div>
              <div className="muted" style={{ fontSize: 13 }}>
                {t.desc}
              </div>
            </Link>
          ))}
        </div>
      </section>

      {error && <p className="error">{error}</p>}
    </div>
  );
}
