"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth";
import { ApiError, TraceSummary, api } from "@/lib/api";

const CHAINS = [
  "ethereum",
  "bitcoin",
  "solana",
  "tron",
  "arbitrum",
  "optimism",
  "base",
  "polygon",
];

// Live client-side chain HINT from the address shape — mirrors the order of the
// server's checksum-verified detect_chain (which is authoritative). This is only
// for instant UX feedback; the backend re-derives it on submit. EVM 0x-addresses
// can't be narrowed past the family, so we hint "ethereum" and let the user pick
// the specific EVM chain.
function detectChainHint(addr: string): string | null {
  const a = addr.trim();
  if (/^0x[0-9a-fA-F]{40}$/.test(a)) return "ethereum";
  if (/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(a)) return "tron";
  if (/^(bc1[0-9a-z]{6,}|[13][1-9A-HJ-NP-Za-km-z]{25,34})$/.test(a)) return "bitcoin";
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(a)) return "solana";
  return null;
}

function statusBadge(status: string) {
  const cls =
    status === "complete" ? "ok" : status === "failed" ? "warn" : "muted";
  return <span className={`badge ${cls}`}>{status}</span>;
}

export default function TracesPage() {
  const { token } = useAuth();
  const [traces, setTraces] = useState<TraceSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Guided "start a recovery" form.
  const [seed, setSeed] = useState("");
  const [chain, setChain] = useState(CHAINS[0]);
  const [chainTouched, setChainTouched] = useState(false);
  const [detected, setDetected] = useState<string | null>(null);
  const [incident, setIncident] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const { traces } = await api.listTraces(token);
      setTraces(traces);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "failed to load traces");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Paste-an-address-first: detect the chain from the shape and auto-select it
  // (until the user overrides the dropdown, which we then respect).
  function onSeedChange(value: string) {
    setSeed(value);
    const hint = detectChainHint(value);
    setDetected(hint);
    if (hint && !chainTouched) setChain(hint);
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!token) return;
    setSubmitting(true);
    setNotice(null);
    setError(null);
    try {
      const iso = new Date(incident).toISOString();
      // Idempotency key so a double-click / retry never enqueues (or bills) twice.
      const idem = `${chain}:${seed.trim()}:${iso}`;
      const res = await api.submitTrace(
        token,
        { chain, seed_address: seed.trim(), incident_time: iso },
        idem,
      );
      setNotice(
        res.idempotent_replay
          ? `Already submitted (${res.investigation_id.slice(0, 8)}…)`
          : `Tracing on ${res.chain} — ${res.investigation_id.slice(0, 8)}… (${res.quota_remaining} left this period)`,
      );
      setSeed("");
      setDetected(null);
      setChainTouched(false);
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "submit failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="stack" style={{ gap: 24 }}>
      <section className="panel">
        <h3 style={{ marginTop: 0 }}>Start a recovery</h3>
        <p className="muted" style={{ marginTop: 0 }}>
          Paste the wallet address that was drained — we detect the chain and
          trace where the funds went.
        </p>
        <form className="stack" onSubmit={onSubmit}>
          <div className="stack">
            <label htmlFor="seed">Drained wallet address</label>
            <input
              id="seed"
              className="mono"
              value={seed}
              onChange={(e) => onSeedChange(e.target.value)}
              placeholder="0x… / bc1… / T… / a Solana address"
              autoComplete="off"
              spellCheck={false}
              required
            />
            {seed.trim() && (
              <span className="muted" style={{ fontSize: 12 }}>
                {detected ? (
                  <>
                    <span
                      style={{
                        display: "inline-block",
                        width: 7,
                        height: 7,
                        borderRadius: "50%",
                        background: "var(--emerald)",
                        marginRight: 6,
                        verticalAlign: "middle",
                      }}
                    />
                    Detected <strong>{detected}</strong>
                    {detected === "ethereum" && " (EVM — change below if it was on another EVM chain)"}
                  </>
                ) : (
                  "Unrecognized address shape — pick the chain below."
                )}
              </span>
            )}
          </div>
          <div className="row">
            <div className="stack" style={{ flex: 1, minWidth: 180 }}>
              <label htmlFor="chain">Chain{detected ? " (auto-detected)" : ""}</label>
              <select
                id="chain"
                value={chain}
                onChange={(e) => {
                  setChain(e.target.value);
                  setChainTouched(true);
                }}
              >
                {CHAINS.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </div>
            <div className="stack" style={{ flex: 1, minWidth: 220 }}>
              <label htmlFor="incident">When did it happen? (UTC)</label>
              <input
                id="incident"
                type="datetime-local"
                value={incident}
                onChange={(e) => setIncident(e.target.value)}
                required
              />
            </div>
          </div>
          <div className="row">
            <button type="submit" disabled={submitting}>
              {submitting ? "Submitting…" : "Trace the funds"}
            </button>
            {notice && <span className="muted">{notice}</span>}
            {error && <span className="error">{error}</span>}
          </div>
        </form>
      </section>

      <section className="panel">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <h3 style={{ margin: 0 }}>Recent traces</h3>
          <button className="ghost" onClick={refresh} disabled={loading}>
            {loading ? "…" : "Refresh"}
          </button>
        </div>
        {traces.length === 0 && !loading ? (
          <p className="muted">No traces yet — start one above.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Case</th>
                <th>Chain</th>
                <th>Status</th>
                <th>Submitted</th>
                <th>ID</th>
              </tr>
            </thead>
            <tbody>
              {traces.map((t) => (
                <tr key={t.investigation_id}>
                  <td>{t.case_id || "—"}</td>
                  <td>{t.chain}</td>
                  <td>{statusBadge(t.status)}</td>
                  <td className="muted">
                    {t.created_at
                      ? new Date(t.created_at).toLocaleString()
                      : "—"}
                  </td>
                  <td className="mono">
                    <Link href={`/dashboard/traces/${t.investigation_id}`}>
                      {t.investigation_id.slice(0, 8)}…
                    </Link>
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
