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

  // submit form
  const [chain, setChain] = useState(CHAINS[0]);
  const [seed, setSeed] = useState("");
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

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!token) return;
    setSubmitting(true);
    setNotice(null);
    setError(null);
    try {
      const iso = new Date(incident).toISOString();
      // Idempotency key so a double-click / retry never enqueues (or bills) twice.
      const idem = `${chain}:${seed}:${iso}`;
      const res = await api.submitTrace(
        token,
        { chain, seed_address: seed, incident_time: iso },
        idem,
      );
      setNotice(
        res.idempotent_replay
          ? `Already submitted (${res.investigation_id.slice(0, 8)}…)`
          : `Queued ${res.investigation_id.slice(0, 8)}… — ${res.quota_remaining} left this period`,
      );
      setSeed("");
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
        <h3 style={{ marginTop: 0 }}>New trace</h3>
        <form className="stack" onSubmit={onSubmit}>
          <div className="row">
            <div className="stack" style={{ flex: 1, minWidth: 160 }}>
              <label htmlFor="chain">Chain</label>
              <select
                id="chain"
                value={chain}
                onChange={(e) => setChain(e.target.value)}
              >
                {CHAINS.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </div>
            <div className="stack" style={{ flex: 2, minWidth: 260 }}>
              <label htmlFor="seed">Seed address</label>
              <input
                id="seed"
                className="mono"
                value={seed}
                onChange={(e) => setSeed(e.target.value)}
                placeholder="0x… / bc1… / T…"
                required
              />
            </div>
            <div className="stack" style={{ flex: 1, minWidth: 200 }}>
              <label htmlFor="incident">Incident time (UTC)</label>
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
              {submitting ? "Submitting…" : "Trace funds"}
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
          <p className="muted">No traces yet — submit one above.</p>
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
