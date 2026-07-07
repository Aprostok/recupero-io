"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { ApiError, TraceDetail, api } from "@/lib/api";

// Standard deliverables the worker writes into a case dir. A download is a
// presigned S3 URL from GET /v2/traces/{id}/artifacts/{name} (501 if object
// storage isn't configured; the button then just reports that).
const ARTIFACTS = [
  { name: "brief.pdf", label: "Investigation brief (PDF)" },
  { name: "transfers.csv", label: "Transfers (CSV)" },
  { name: "trace_report.html", label: "Trace report (HTML)" },
  { name: "exhibit_pack.zip", label: "Exhibit pack (ZIP)" },
];

const ACTIVE = new Set(["queued", "running", "processing", "claimed"]);

function statusBadge(status: string) {
  const cls =
    status === "complete" ? "ok" : status === "failed" ? "warn" : "muted";
  return <span className={`badge ${cls}`}>{status}</span>;
}

export default function TraceDetailPage() {
  const { token } = useAuth();
  const params = useParams<{ id: string }>();
  const id = params?.id as string;

  const [trace, setTrace] = useState<TraceDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

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

  // Live updates while the trace is running: prefer SSE (GET /v2/traces/{id}/
  // stream), fall back to polling if EventSource errors or is unavailable.
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
              load(); // refresh full detail (timestamps) on terminal status
            }
          }
        } catch {
          /* ignore keep-alive / malformed frames */
        }
      };
      es.onerror = () => es.close(); // fall through to the poll below
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
                <div>{trace.chain}</div>
              </div>
              <div>
                <label>Seed address</label>
                <div className="mono">{trace.seed_address}</div>
              </div>
            </div>
            <div className="row" style={{ gap: 32 }}>
              <div>
                <label>Submitted</label>
                <div className="muted">
                  {trace.created_at ? new Date(trace.created_at).toLocaleString() : "—"}
                </div>
              </div>
              <div>
                <label>Updated</label>
                <div className="muted">
                  {trace.updated_at ? new Date(trace.updated_at).toLocaleString() : "—"}
                </div>
              </div>
              <div>
                <label>ID</label>
                <div className="mono">{trace.investigation_id}</div>
              </div>
            </div>
          </section>

          <section className="panel">
            <h3 style={{ marginTop: 0 }}>Deliverables</h3>
            {trace.status !== "complete" ? (
              <p className="muted">
                Available once the trace completes.
              </p>
            ) : (
              <div className="row">
                <button onClick={() => download("interactive_graph.html")}>
                  Fund-flow graph
                </button>
                {ARTIFACTS.map((a) => (
                  <button key={a.name} className="ghost" onClick={() => download(a.name)}>
                    {a.label}
                  </button>
                ))}
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
