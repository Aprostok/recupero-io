"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { ApiError, CaseSummary, Me, TraceDetail, api } from "@/lib/api";

// Deliverables/tools, each tagged with the entitlement (tenancy FEATURE_* key)
// that unlocks it. `feature: null` = available on every plan (basic). Locked
// tools render disabled with an "Upgrade to unlock" link — the consumer
// progressive-unlock surface, driven by /v2/me `features`.
const TOOLS: { name: string; label: string; feature: string | null }[] = [
  { name: "brief.pdf", label: "Investigation brief (PDF)", feature: "deliverable.brief" },
  { name: "transfers.csv", label: "Transfers (CSV)", feature: null },
  { name: "trace_report.html", label: "Trace report (HTML)", feature: null },
  { name: "exhibit_pack.zip", label: "Exhibit pack (ZIP)", feature: "deliverable.exhibit_pack" },
];

const ACTIVE = new Set(["queued", "running", "processing", "claimed"]);

function statusBadge(status: string) {
  const cls =
    status === "complete" ? "ok" : status === "failed" ? "warn" : "muted";
  return <span className={`badge ${cls}`}>{status}</span>;
}

// Compact USD for stat tiles ("$1.2M"); the brief's own display strings are used
// where available so the customer sees the same figures as the PDF.
function fmtUsd(n: number | null): string {
  if (n === null || Number.isNaN(n)) return "—";
  const abs = Math.abs(n);
  if (abs >= 1e9) return `$${(n / 1e9).toFixed(2)}B`;
  if (abs >= 1e6) return `$${(n / 1e6).toFixed(2)}M`;
  if (abs >= 1e3) return `$${(n / 1e3).toFixed(1)}K`;
  return `$${n.toFixed(0)}`;
}

// Map a brief endpoint status to a card accent.
function endpointClass(status: string | null): string {
  const s = (status || "").toUpperCase();
  if (s === "FREEZABLE") return "freezable";
  if (s === "EXCHANGE") return "exchange";
  if (s === "UNRECOVERABLE" || s === "BURNED") return "unrecoverable";
  return "";
}

function short(addr: string): string {
  return addr.length > 14 ? `${addr.slice(0, 8)}…${addr.slice(-6)}` : addr;
}

export default function TraceDetailPage() {
  const { token } = useAuth();
  const params = useParams<{ id: string }>();
  const id = params?.id as string;

  const [trace, setTrace] = useState<TraceDetail | null>(null);
  const [summary, setSummary] = useState<CaseSummary | null>(null);
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [graphUrl, setGraphUrl] = useState<string | null>(null);

  // Plan entitlements, for unlocked/locked tool rendering (best-effort).
  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    api.me(token).then((m) => !cancelled && setMe(m)).catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [token]);

  // A tool is locked only once we KNOW the plan (me loaded) and it lacks the
  // feature — avoids a flash of "locked" before entitlements arrive.
  const isLocked = (feature: string | null): boolean =>
    feature !== null && me !== null && !me.features.includes(feature);

  const load = useCallback(async () => {
    if (!token || !id) return;
    try {
      setTrace(await api.getTrace(token, id));
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "failed to load trace");
    }
  }, [token, id]);

  useEffect(() => {
    load();
  }, [load]);

  // Once complete, pull the consumer "where's my money now" summary. Best-effort:
  // a 404 just means the brief isn't ready yet (leave the panel out silently).
  useEffect(() => {
    if (!token || !id || trace?.status !== "complete" || summary) return;
    let cancelled = false;
    api
      .getSummary(token, id)
      .then((s) => {
        if (!cancelled) setSummary(s);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [token, id, trace?.status, summary]);

  // Live updates while running: prefer SSE, fall back to polling.
  useEffect(() => {
    if (!token || !id || !trace || !ACTIVE.has(trace.status)) return;

    if (typeof EventSource !== "undefined") {
      const es = new EventSource(api.streamUrl(id, token));
      es.onmessage = (ev) => {
        try {
          const data = JSON.parse(ev.data);
          if (data.status) {
            setTrace((prev) => (prev ? { ...prev, status: data.status } : prev));
            if (!ACTIVE.has(data.status)) {
              es.close();
              load();
            }
          }
        } catch {
          /* ignore keep-alive / malformed frames */
        }
      };
      es.onerror = () => es.close();
      return () => es.close();
    }

    const t = setInterval(load, 4000);
    return () => clearInterval(t);
  }, [token, id, trace, load]);

  async function download(name: string) {
    if (!token || !id) return;
    setNotice(null);
    setError(null);
    try {
      const { url } = await api.getArtifactUrl(token, id, name);
      window.open(url, "_blank", "noopener");
    } catch (err) {
      if (err instanceof ApiError && err.status === 501) {
        setNotice("Artifact storage isn't configured on this deployment.");
      } else if (err instanceof ApiError && err.status === 404) {
        setNotice(`"${name}" isn't available for this trace yet.`);
      } else {
        setError(err instanceof ApiError ? err.detail : "download failed");
      }
    }
  }

  // Load the engine's self-contained interactive D3 graph (pan/zoom/click/
  // risk-coloured) into an inline iframe — the in-app investigation graph.
  async function loadGraph() {
    if (!token || !id) return;
    setNotice(null);
    setError(null);
    try {
      const { url } = await api.getArtifactUrl(token, id, "interactive_graph.html");
      setGraphUrl(url);
    } catch (err) {
      if (err instanceof ApiError && err.status === 501) {
        setNotice("The interactive graph needs object storage configured on this deployment.");
      } else if (err instanceof ApiError && err.status === 404) {
        setNotice("The interactive graph isn't available for this trace yet.");
      } else {
        setError(err instanceof ApiError ? err.detail : "failed to load graph");
      }
    }
  }

  // Recoverability split (of total loss) for the hero bar.
  const loss = summary?.totals.loss_usd ?? null;
  const recoverable = summary?.totals.max_recoverable_usd ?? null;
  const recoverablePct =
    loss && loss > 0 && recoverable !== null
      ? Math.max(0, Math.min(100, (recoverable / loss) * 100))
      : 0;

  return (
    <div className="stack" style={{ gap: 24 }}>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <Link href="/dashboard" className="muted">
          ← Traces
        </Link>
        {trace && ACTIVE.has(trace.status) && (
          <span className="muted">auto-refreshing…</span>
        )}
      </div>

      {error && <div className="error">{error}</div>}
      {!trace && !error && <p className="muted">Loading…</p>}

      {trace && (
        <>
          <section className="panel stack">
            <div className="row" style={{ justifyContent: "space-between" }}>
              <h3 style={{ margin: 0 }}>{trace.case_id || "Trace"}</h3>
              {statusBadge(trace.status)}
            </div>
            <div className="row" style={{ gap: 32 }}>
              <div>
                <label>Chain</label>
                <div>{summary?.chain || trace.chain}</div>
              </div>
              <div>
                <label>Seed address</label>
                <div className="mono">{trace.seed_address}</div>
              </div>
              {summary?.incident_type && (
                <div>
                  <label>Incident</label>
                  <div>{summary.incident_type}</div>
                </div>
              )}
            </div>
          </section>

          {/* ── "Where's my money now" — the consumer recoverability view ── */}
          {summary && (
            <>
              <section className="panel stack" style={{ gap: 18 }}>
                <div className="row" style={{ justifyContent: "space-between" }}>
                  <h3 style={{ margin: 0 }}>Where your money is now</h3>
                  {summary.totals_display.recoverable_percent && (
                    <span className="badge ok">
                      {summary.totals_display.recoverable_percent} recoverable
                    </span>
                  )}
                </div>

                {summary.recovery.headline && (
                  <p className="muted" style={{ margin: 0 }}>
                    {summary.recovery.headline}
                  </p>
                )}

                <div className="hero-metrics">
                  <div className="stat-tile">
                    <div className="k">Total traced</div>
                    <div className="v">
                      {summary.totals_display.loss_usd || fmtUsd(summary.totals.loss_usd)}
                    </div>
                  </div>
                  <div className="stat-tile good">
                    <div className="k">Potentially recoverable</div>
                    <div className="v">
                      {summary.totals_display.max_recoverable_usd ||
                        fmtUsd(summary.totals.max_recoverable_usd)}
                    </div>
                  </div>
                  <div className="stat-tile">
                    <div className="k">Net to you (est.)</div>
                    <div className="v">
                      {fmtUsd(summary.recovery.expected_net_to_victim_usd)}
                    </div>
                  </div>
                </div>

                {/* Proportional recoverable / gone bar */}
                <div className="stack" style={{ gap: 8 }}>
                  <div className="recover-bar" aria-hidden>
                    <div
                      className="recover-seg good"
                      style={{ width: `${recoverablePct}%` }}
                    />
                    <div
                      className="recover-seg bad"
                      style={{ width: `${100 - recoverablePct}%` }}
                    />
                  </div>
                  <div className="recover-legend">
                    <span>
                      <i style={{ background: "var(--emerald)" }} />
                      Potentially recoverable
                    </span>
                    <span>
                      <i style={{ background: "var(--danger)" }} />
                      Unrecoverable (mixed / burned / gone)
                    </span>
                  </div>
                </div>
              </section>

              {summary.endpoints.length > 0 && (
                <section className="panel stack">
                  <h3 style={{ marginTop: 0 }}>
                    Fund endpoints{" "}
                    <span className="muted" style={{ fontWeight: 400 }}>
                      ({summary.endpoint_count})
                    </span>
                  </h3>
                  <div className="endpoint-grid">
                    {summary.endpoints.slice(0, 60).map((e, i) => (
                      <div
                        key={`${e.address}-${i}`}
                        className={`endpoint-card ${endpointClass(e.status)}`}
                      >
                        <div
                          className="row"
                          style={{ justifyContent: "space-between", marginBottom: 6 }}
                        >
                          <span className="st">{e.status || "TRANSIT"}</span>
                          <span style={{ fontWeight: 700 }}>
                            {fmtUsd(e.usd_holding_now ?? e.usd_received)}
                          </span>
                        </div>
                        <div className="mono" title={e.address}>
                          {short(e.address)}
                        </div>
                        <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                          {[e.chain, e.role].filter(Boolean).join(" · ") || "—"}
                        </div>
                        {e.note && (
                          <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                            {e.note}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </section>
              )}

              {summary.next_steps.length > 0 && (
                <section className="panel stack">
                  <h3 style={{ marginTop: 0 }}>Recommended next steps</h3>
                  <ol className="next-steps">
                    {summary.next_steps.map((s, i) => (
                      <li key={i}>{typeof s === "string" ? s : JSON.stringify(s)}</li>
                    ))}
                  </ol>
                </section>
              )}
            </>
          )}

          {/* ── Interactive fund-flow graph (inline, in-app) ── */}
          {trace.status === "complete" && !isLocked("graph") && (
            <section className="panel stack">
              <div className="row" style={{ justifyContent: "space-between" }}>
                <h3 style={{ margin: 0 }}>Fund-flow graph</h3>
                {!graphUrl && (
                  <button onClick={loadGraph}>Load interactive graph</button>
                )}
              </div>
              {graphUrl ? (
                <iframe
                  src={graphUrl}
                  title="Interactive fund-flow graph"
                  sandbox="allow-scripts allow-same-origin allow-popups"
                  style={{
                    width: "100%",
                    height: 580,
                    border: "1px solid var(--border)",
                    borderRadius: "var(--r)",
                    background: "var(--panel)",
                  }}
                />
              ) : (
                <p className="muted" style={{ margin: 0 }}>
                  Pan / zoom / click-to-highlight, risk-coloured, multi-chain — opens right here in the page.
                </p>
              )}
            </section>
          )}

          <section className="panel">
            <h3 style={{ marginTop: 0 }}>Deliverables</h3>
            {trace.status !== "complete" ? (
              <p className="muted">Available once the trace completes.</p>
            ) : (
              <div className="row">
                {TOOLS.map((t) =>
                  isLocked(t.feature) ? (
                    <span key={t.name} className="row" style={{ gap: 6 }}>
                      <button
                        className="ghost"
                        disabled
                        title="Not included in your plan"
                      >
                        🔒 {t.label}
                      </button>
                      <Link
                        href="/dashboard/billing"
                        className="muted"
                        style={{ fontSize: 12 }}
                      >
                        Upgrade
                      </Link>
                    </span>
                  ) : (
                    <button
                      key={t.name}
                      className={t.feature === "graph" ? "" : "ghost"}
                      onClick={() => download(t.name)}
                    >
                      {t.label}
                    </button>
                  ),
                )}
              </div>
            )}
            {notice && (
              <p className="muted" style={{ marginBottom: 0 }}>
                {notice}
              </p>
            )}
          </section>
        </>
      )}
    </div>
  );
}
