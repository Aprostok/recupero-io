"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";
import {
  ApiError,
  GuardCheckResult,
  WalletAlert,
  WatchedAddress,
  api,
} from "@/lib/api";

const CHAINS = [
  "ethereum",
  "bitcoin",
  "solana",
  "tron",
  "polygon",
  "arbitrum",
  "base",
  "optimism",
];

/** Colour + label for a screener verdict. */
function verdictStyle(verdict: string | null): { color: string; bg: string } {
  switch (verdict) {
    case "sanctioned":
    case "high":
      return { color: "var(--danger)", bg: "rgba(255,93,108,.12)" };
    case "medium":
      return { color: "var(--warn)", bg: "rgba(255,190,77,.12)" };
    case "low":
      return { color: "var(--accent)", bg: "rgba(61,123,255,.12)" };
    case "clean":
      return { color: "var(--ok)", bg: "rgba(53,210,154,.12)" };
    default:
      return { color: "var(--muted)", bg: "rgba(255,255,255,.06)" };
  }
}

function VerdictBadge({ verdict }: { verdict: string | null }) {
  const s = verdictStyle(verdict);
  return (
    <span
      className="chip"
      style={{ color: s.color, background: s.bg, border: `1px solid ${s.color}55` }}
    >
      <span style={{ width: 7, height: 7, borderRadius: "50%", background: s.color, display: "inline-block" }} />
      {verdict ?? "unchecked"}
    </span>
  );
}

/** Clean SVG glyph for a guard action (block / warn / allow) — no emoji. */
function GuardIcon({ action }: { action: "block" | "warn" | "allow" }) {
  const p = {
    width: 20,
    height: 20,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 2,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true,
  };
  if (action === "block")
    return (
      <svg {...p}>
        <circle cx="12" cy="12" r="9" />
        <path d="M6.3 6.3l11.4 11.4" />
      </svg>
    );
  if (action === "warn")
    return (
      <svg {...p}>
        <path d="M12 3.2l9.3 16.1a1 1 0 0 1-.87 1.5H3.57a1 1 0 0 1-.87-1.5z" />
        <path d="M12 9.5v4M12 17h.01" />
      </svg>
    );
  return (
    <svg {...p}>
      <circle cx="12" cy="12" r="9" />
      <path d="M8 12.2l2.6 2.6L16 9.4" />
    </svg>
  );
}

export default function GuardPage() {
  const { token } = useAuth();
  const [addresses, setAddresses] = useState<WatchedAddress[]>([]);
  const [alerts, setAlerts] = useState<WalletAlert[]>([]);
  const [unacked, setUnacked] = useState(0);
  const [error, setError] = useState<string | null>(null);

  // pre-send check box
  const [checkAddr, setCheckAddr] = useState("");
  const [checkChain, setCheckChain] = useState("ethereum");
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<GuardCheckResult | null>(null);

  // add-to-book form
  const [addLabel, setAddLabel] = useState("");
  const [adding, setAdding] = useState(false);

  const refresh = useCallback(async () => {
    if (!token) return;
    setError(null);
    try {
      const [{ addresses }, { alerts, unacknowledged }] = await Promise.all([
        api.listWatched(token),
        api.listAlerts(token),
      ]);
      setAddresses(addresses);
      setAlerts(alerts);
      setUnacked(unacknowledged);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "failed to load");
    }
  }, [token]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function onCheck(e: FormEvent) {
    e.preventDefault();
    if (!token) return;
    setChecking(true);
    setError(null);
    setResult(null);
    try {
      const res = await api.guardCheck(token, checkAddr.trim(), checkChain);
      setResult(res);
      if (res.alert_id) await refresh(); // a new alert may have been raised
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "check failed");
    } finally {
      setChecking(false);
    }
  }

  async function onAddToBook() {
    if (!token || !result) return;
    setAdding(true);
    setError(null);
    try {
      await api.addWatched(
        token,
        result.screening.address,
        result.screening.chain || checkChain,
        addLabel.trim() || undefined,
      );
      setAddLabel("");
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "add failed");
    } finally {
      setAdding(false);
    }
  }

  async function onRemove(id: string) {
    if (!token) return;
    try {
      await api.deleteWatched(token, id);
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "remove failed");
    }
  }

  async function onAck(id: string) {
    if (!token) return;
    try {
      await api.ackAlert(token, id);
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "ack failed");
    }
  }

  const guard = result?.guard;
  const guardColor =
    guard?.action === "block"
      ? "var(--danger)"
      : guard?.action === "warn"
        ? "var(--warn)"
        : "var(--ok)";

  return (
    <div className="stack" style={{ gap: 24 }}>
      {/* ── Pre-send check ── */}
      <section className="panel">
        <h3 style={{ marginTop: 0 }}>Check before you send</h3>
        <p className="muted" style={{ marginTop: -4 }}>
          Screen a recipient address against live sanctions data, known mixers,
          drainers, and prior-case attribution before you send funds.
        </p>
        <form className="row" onSubmit={onCheck}>
          <select value={checkChain} onChange={(e) => setCheckChain(e.target.value)}>
            {CHAINS.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
          <input
            className="mono"
            style={{ flex: 1, minWidth: 260 }}
            value={checkAddr}
            onChange={(e) => setCheckAddr(e.target.value)}
            placeholder="recipient address (e.g. 0x…)"
            required
          />
          <button type="submit" disabled={checking}>
            {checking ? "Checking…" : "Check address"}
          </button>
        </form>

        {guard && result && (
          <div
            className="stack"
            style={{
              marginTop: 16,
              gap: 8,
              padding: 16,
              borderRadius: 12,
              border: `1px solid ${guardColor}55`,
              background: `${guardColor}12`,
            }}
          >
            <div className="row" style={{ justifyContent: "space-between" }}>
              <strong style={{ color: guardColor, fontSize: 18, display: "inline-flex", alignItems: "center", gap: 8 }}>
                <GuardIcon action={guard.action} />
                {guard.title}
              </strong>
              <VerdictBadge verdict={guard.verdict} />
            </div>
            <div>{guard.headline}</div>
            <div className="muted">{guard.advice}</div>
            <div className="row" style={{ marginTop: 6 }}>
              <input
                style={{ flex: 1, minWidth: 180 }}
                value={addLabel}
                onChange={(e) => setAddLabel(e.target.value)}
                placeholder="label (optional) — e.g. 'suspected scammer'"
              />
              <button className="ghost" onClick={onAddToBook} disabled={adding}>
                {adding ? "Adding…" : "Add to address book"}
              </button>
            </div>
          </div>
        )}
        {error && (
          <div className="error" style={{ marginTop: 8 }}>
            {error}
          </div>
        )}
      </section>

      {/* ── Alerts ── */}
      <section className="panel">
        <h3 style={{ marginTop: 0 }}>
          Alerts{" "}
          {unacked > 0 && (
            <span className="chip" style={{ color: "var(--danger)", background: "rgba(255,93,108,.12)" }}>
              {unacked} unacknowledged
            </span>
          )}
        </h3>
        {alerts.length === 0 ? (
          <p className="muted">No alerts. Risky checks and watched addresses appear here.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Address</th>
                <th>Verdict</th>
                <th>Finding</th>
                <th>When</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((a) => (
                <tr key={a.id} style={{ opacity: a.acknowledged ? 0.5 : 1 }}>
                  <td className="mono">
                    {a.address.slice(0, 10)}…{a.address.slice(-6)}
                  </td>
                  <td>
                    <VerdictBadge verdict={a.verdict} />
                  </td>
                  <td>{a.headline}</td>
                  <td className="muted">{new Date(a.created_at).toLocaleString()}</td>
                  <td>
                    {a.acknowledged ? (
                      <span className="badge muted">acknowledged</span>
                    ) : (
                      <button className="ghost" onClick={() => onAck(a.id)}>
                        Acknowledge
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {/* ── Address book ── */}
      <section className="panel">
        <h3 style={{ marginTop: 0 }}>Address book</h3>
        <p className="muted" style={{ marginTop: -4 }}>
          Addresses you watch. Each is screened on add; its cached verdict is
          shown below.
        </p>
        {addresses.length === 0 ? (
          <p className="muted">
            No watched addresses yet. Check an address above and add it here.
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Label</th>
                <th>Chain</th>
                <th>Address</th>
                <th>Verdict</th>
                <th>Checked</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {addresses.map((w) => (
                <tr key={w.id}>
                  <td>{w.label || <span className="muted">—</span>}</td>
                  <td className="muted">{w.chain}</td>
                  <td className="mono">
                    {w.address.slice(0, 10)}…{w.address.slice(-6)}
                  </td>
                  <td>
                    <VerdictBadge verdict={w.last_verdict} />
                  </td>
                  <td className="muted">
                    {w.last_checked_at
                      ? new Date(w.last_checked_at).toLocaleDateString()
                      : "—"}
                  </td>
                  <td>
                    <button className="danger" onClick={() => onRemove(w.id)}>
                      Remove
                    </button>
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
