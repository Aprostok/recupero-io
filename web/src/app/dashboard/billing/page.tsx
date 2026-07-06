"use client";

import { useCallback, useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";
import { ApiError, BillingUsage, api } from "@/lib/api";

const UPGRADE_TARGETS = ["pro", "enterprise"];

export default function BillingPage() {
  const { token } = useAuth();
  const [usage, setUsage] = useState<BillingUsage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

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

      <section className="panel">
        <h3 style={{ marginTop: 0 }}>Upgrade</h3>
        <div className="row">
          {UPGRADE_TARGETS.filter((p) => p !== usage.plan).map((p) => (
            <button key={p} onClick={() => onUpgrade(p)}>
              Upgrade to {p}
            </button>
          ))}
        </div>
        {notice && (
          <p className="muted" style={{ marginBottom: 0 }}>
            {notice}
          </p>
        )}
        {error && <p className="error">{error}</p>}
        {!usage.billing_configured && (
          <p className="muted" style={{ fontSize: 12, marginBottom: 0 }}>
            No payment method on file.
          </p>
        )}
      </section>
    </div>
  );
}
