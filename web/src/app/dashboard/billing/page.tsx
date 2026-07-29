"use client";

import { useCallback, useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";
import { ApiError, BillingUsage, Entitlements, api } from "@/lib/api";

const UPGRADE_TARGETS = ["pro", "enterprise"];

// Self-serve subscriptions are NOT sold today — Recupero is delivered as a managed
// engagement (flat diagnostic first run, then per-case pricing, plus a contingency
// fee on recovered funds). Showing "Upgrade to pro" would advertise a product that
// cannot be bought, so the upgrade CTAs stay hidden until this flips to true. The
// Stripe checkout path underneath is intact and tested — flip this one constant on
// the day self-serve goes live.
const SELF_SERVE_BILLING = false;

// Human labels for the tenancy FEATURE_* keys (unknown keys fall back to the raw
// key so a newly-added feature still renders).
const FEATURE_LABELS: Record<string, string> = {
  screening: "Address screening",
  "trace.basic": "Basic tracing",
  "trace.deep_reach": "Deep-reach tracing",
  "chains.evm": "EVM chains",
  "chains.all": "All chains (Solana, Tron, BTC, …)",
  graph: "Interactive fund-flow graph",
  recovery_view: "Recovery view",
  "deliverable.brief": "Investigation brief (PDF)",
  "deliverable.exhibit_pack": "Court exhibit pack",
  monitoring: "Address monitoring & alerts",
  api_access: "Programmatic API access",
  litigation_artifacts: "Litigation artifacts (SAR/STR, LE handoff)",
  "attribution.misttrack": "MistTrack attribution",
  demix_leads: "Mixer demixing leads",
  cooperation_intel: "Exchange cooperation intel",
  bulk_screening: "Bulk screening",
  audit_log: "Audit log",
  sso: "SSO / SAML",
};

const featureLabel = (k: string) => FEATURE_LABELS[k] ?? k;

export default function BillingPage() {
  const { token } = useAuth();
  const [usage, setUsage] = useState<BillingUsage | null>(null);
  const [ent, setEnt] = useState<Entitlements | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Plan entitlements — "what your plan includes" (best-effort; never blocks billing).
  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    api.entitlements(token).then((e) => !cancelled && setEnt(e)).catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [token]);

  const refresh = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      setUsage(await api.billingUsage(token));
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "failed to load billing");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function onUpgrade(plan: string) {
    if (!token) return;
    setError(null);
    setNotice(null);
    try {
      const { checkout_url } = await api.checkout(token, plan);
      window.location.href = checkout_url;
    } catch (err) {
      if (err instanceof ApiError && err.status === 501) {
        setNotice("Self-serve billing isn't enabled yet — contact sales.");
      } else {
        setError(err instanceof ApiError ? err.detail : "checkout failed");
      }
    }
  }

  if (loading || !usage) {
    return (
      <p className="muted">{error ? <span className="error">{error}</span> : "Loading…"}</p>
    );
  }

  const included = usage.traces_included < 0 ? "unlimited" : usage.traces_included;
  const remaining =
    usage.traces_remaining < 0 ? "unlimited" : usage.traces_remaining;

  return (
    <div className="stack" style={{ gap: 24 }}>
      <section className="panel">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <div>
            <label>Current plan</label>
            <div className="metric" style={{ textTransform: "capitalize" }}>
              {usage.plan}{" "}
              <span
                className={`badge ${usage.status === "active" ? "ok" : "warn"}`}
              >
                {usage.status}
              </span>
            </div>
          </div>
          <div>
            <label>Renews</label>
            <div>
              {usage.plan_renews_at
                ? new Date(usage.plan_renews_at).toLocaleDateString()
                : "—"}
            </div>
          </div>
        </div>
      </section>

      <section className="row" style={{ alignItems: "stretch" }}>
        <div className="panel" style={{ flex: 1 }}>
          <label>Traces this period</label>
          <div className="metric">
            {usage.traces_used}
            <span className="muted" style={{ fontSize: 14 }}>
              {" "}
              / {included}
            </span>
          </div>
          <div className="muted">{remaining} remaining</div>
        </div>
        <div className="panel" style={{ flex: 1 }}>
          <label>Rate limit</label>
          <div className="metric">{usage.rate_limit_per_min}</div>
          <div className="muted">requests / min</div>
        </div>
        <div className="panel" style={{ flex: 1 }}>
          <label>Seats</label>
          <div className="metric">
            {usage.seats.used}
            <span className="muted" style={{ fontSize: 14 }}>
              {" "}
              / {usage.seats.max < 0 ? "∞" : usage.seats.max}
            </span>
          </div>
        </div>
      </section>

      {ent && (
        <section className="panel stack">
          <h3 style={{ marginTop: 0 }}>What your plan includes</h3>
          <div className="feature-grid">
            {ent.features.map((f) => (
              <div key={f} className="feat on">
                <span className="tick">✓</span> {featureLabel(f)}
              </div>
            ))}
            {ent.locked.map((f) => (
              <div key={f} className="feat off">
                <span className="tick">🔒</span> {featureLabel(f)}
              </div>
            ))}
          </div>
          {ent.locked.length > 0 && (
            <p className="muted" style={{ margin: 0, fontSize: 13 }}>
              {SELF_SERVE_BILLING
                ? "🔒 items unlock on a higher plan — upgrade below."
                : "🔒 items aren't included in your current plan — ask us about adding them."}
            </p>
          )}
        </section>
      )}

      <section className="panel">
        <h3 style={{ marginTop: 0 }}>
          {SELF_SERVE_BILLING ? "Upgrade" : "Changing your plan"}
        </h3>
        {SELF_SERVE_BILLING ? (
          <div className="row">
            {UPGRADE_TARGETS.filter((p) => p !== usage.plan).map((p) => (
              <button key={p} onClick={() => onUpgrade(p)}>
                Upgrade to {p}
              </button>
            ))}
          </div>
        ) : (
          <p className="muted" style={{ marginTop: 0 }}>
            Your plan is set up with you directly as part of your engagement — there is no
            self-serve upgrade to buy. To change what&rsquo;s included, or to discuss a case,{" "}
            <a href="/contact">get in touch</a>.
          </p>
        )}
        {notice && (
          <p className="muted" style={{ marginBottom: 0 }}>
            {notice}
          </p>
        )}
        {error && <p className="error">{error}</p>}
        {SELF_SERVE_BILLING && !usage.billing_configured && (
          <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
            No payment method on file.
          </p>
        )}
      </section>
    </div>
  );
}
