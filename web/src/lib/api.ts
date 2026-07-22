/**
 * Typed client for the Recupero `/v2` SaaS API.
 *
 * Every call attaches the Bearer session token (see `auth.tsx`) and normalises
 * errors into `ApiError` (carrying the HTTP status + server `detail`). The base
 * URL comes from `NEXT_PUBLIC_API_BASE_URL` so the frontend can be deployed on a
 * different origin than the API.
 */

const BASE_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000"
).replace(/\/$/, "");

export class ApiError extends Error {
  status: number;
  detail: string;
  constructor(status: number, detail: string) {
    super(`${status}: ${detail}`);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

// ---- response shapes (mirror platform/router.py) ---- //

export interface TokenOut {
  access_token: string;
  token_type: string;
  expires_in: number;
  org_id: string;
}

export interface Me {
  org_id: string;
  role: string;
  user_id: string | null;
  plan: string;
  status: string;
  usage: {
    traces_used: number;
    traces_remaining: number;
    rate_limit_per_min: number;
  };
  // Feature entitlements for this org's plan — the app renders each tool as
  // unlocked (in this list) or locked-with-"Upgrade". Full catalog + locked
  // diff come from getEntitlements().
  features: string[];
}

export interface Entitlements {
  plan: string;
  features: string[];      // unlocked for this plan
  all_features: string[];  // full catalog
  locked: string[];        // catalog minus unlocked → show "Upgrade to unlock"
}

export interface TraceSummary {
  investigation_id: string;
  status: string;
  case_id: string | null;
  chain: string;
  created_at: string;
}

export interface TraceDetail extends TraceSummary {
  seed_address: string;
  updated_at: string;
}

export interface SubmitTraceResult {
  investigation_id: string;
  status: string;
  case_id: string;
  idempotent_replay: boolean;
  poll: string;
  quota_remaining: number;
  submitted_at: string;
}

export interface ApiKeySummary {
  id: string;
  name: string;
  last4: string;
  created_at: string;
  last_used_at: string | null;
  revoked: boolean;
}

export interface NewApiKey {
  api_key: string;
  last4: string;
  warning: string;
}

export interface Member {
  user_id: string;
  email: string;
  name: string | null;
  role: string;
  joined_at: string;
}

export interface Invite {
  id: string;
  email: string;
  role: string;
  created_at: string;
  expires_at: string;
}

export interface NewInvite {
  invite_id: string;
  email: string;
  role: string;
  invite_token: string;
  accept_url: string;
  expires_at: string;
  warning: string;
}

export interface AuditEvent {
  id: number;
  occurred_at: string | null;
  actor: string;
  action: string;
  target: string | null;
  target_kind: string | null;
  outcome: string;
  metadata: Record<string, unknown>;
}

// ---- Wallet Guard (WalletBlock) ---- //

export interface GuardVerdict {
  action: "block" | "warn" | "allow";
  title: string;
  verdict: "sanctioned" | "high" | "medium" | "low" | "clean";
  risk_score: number;
  headline: string;
  advice: string;
  should_alert: boolean;
}

export interface GuardCheckResult {
  screening: {
    address: string;
    chain: string;
    risk_verdict: string;
    risk_score: number;
    labels: { name: string; category: string; severity: number }[];
    investigator_note: string;
    [k: string]: unknown;
  };
  guard: GuardVerdict;
  alert_id: string | null;
}

export interface WatchedAddress {
  id: string;
  chain: string;
  address: string;
  label: string | null;
  last_verdict: string | null;
  last_risk_score: number | null;
  last_checked_at: string | null;
  created_at: string;
}

export interface WalletAlert {
  id: string;
  watched_address_id: string | null;
  chain: string;
  address: string;
  verdict: string;
  severity: number;
  category: string | null;
  headline: string;
  source: string;
  created_at: string;
  acknowledged: boolean;
}

// ---- Investigation graph ---- //

export interface GraphNode {
  id: string;
  label: string;
  chain: string;
  chainColor: string;
  category: string;
  inboundUsdNumeric: number;
  outboundUsdNumeric: number;
  flowUsdNumeric: number;
  isVictim: boolean;
  explorerUrl: string | null;
  risk: string;
  riskColor: string | null;
  [k: string]: unknown;
}

export interface GraphEdge {
  source: string;
  target: string;
  totalUsdNumeric: number;
  transferCount: number;
  isCrossChain: boolean;
  [k: string]: unknown;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  meta: {
    case_id: string;
    seed_address: string;
    node_count: number;
    edge_count: number;
    total_usd_traced: string;
    chain: string;
    chains: string[];
    categories: string[];
    risk_node_count: number;
    risk_categories: string[];
  };
}

export interface BillingUsage {
  plan: string;
  status: string;
  period_start: string;
  plan_renews_at: string | null;
  traces_used: number;
  traces_included: number;
  traces_remaining: number;
  rate_limit_per_min: number;
  seats: { used: number; max: number };
  billing_configured: boolean;
}

// ---- low-level request helper ---- //

interface RequestOpts {
  method?: string;
  body?: unknown;
  token?: string | null;
  headers?: Record<string, string>;
}

async function request<T>(path: string, opts: RequestOpts = {}): Promise<T> {
  const headers: Record<string, string> = { ...(opts.headers || {}) };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (opts.token) headers["Authorization"] = `Bearer ${opts.token}`;

  let res: Response;
  try {
    res = await fetch(`${BASE_URL}${path}`, {
      method: opts.method || "GET",
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      cache: "no-store",
    });
  } catch {
    throw new ApiError(0, "network error — is the API reachable?");
  }

  if (res.status === 204) return undefined as T;

  let data: unknown = null;
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { detail: text };
    }
  }

  if (!res.ok) {
    const detail =
      (data as { detail?: unknown })?.detail != null
        ? String((data as { detail?: unknown }).detail)
        : res.statusText;
    throw new ApiError(res.status, detail);
  }
  return data as T;
}

// ---- API surface ---- //

export const api = {
  signup: (email: string, password: string, org_name: string) =>
    request<TokenOut>("/v2/auth/signup", {
      method: "POST",
      body: { email, password, org_name },
    }),

  login: (email: string, password: string) =>
    request<TokenOut>("/v2/auth/login", {
      method: "POST",
      body: { email, password },
    }),

  me: (token: string) => request<Me>("/v2/me", { token }),

  entitlements: (token: string) =>
    request<Entitlements>("/v2/entitlements", { token }),

  listTraces: (token: string, limit = 50) =>
    request<{ traces: TraceSummary[] }>(`/v2/traces?limit=${limit}`, { token }),

  getTrace: (token: string, id: string) =>
    request<TraceDetail>(`/v2/traces/${encodeURIComponent(id)}`, { token }),

  submitTrace: (
    token: string,
    payload: {
      chain: string;
      seed_address: string;
      incident_time: string;
      case_id?: string;
    },
    idempotencyKey?: string,
  ) =>
    request<SubmitTraceResult>("/v2/traces", {
      method: "POST",
      token,
      body: payload,
      headers: idempotencyKey ? { "Idempotency-Key": idempotencyKey } : {},
    }),

  listKeys: (token: string) =>
    request<{ keys: ApiKeySummary[] }>("/v2/api-keys", { token }),

  createKey: (token: string, name: string) =>
    request<NewApiKey>("/v2/api-keys", {
      method: "POST",
      token,
      body: { name },
    }),

  revokeKey: (token: string, id: string) =>
    request<void>(`/v2/api-keys/${encodeURIComponent(id)}`, {
      method: "DELETE",
      token,
    }),

  billingUsage: (token: string) =>
    request<BillingUsage>("/v2/billing/usage", { token }),

  checkout: (token: string, plan: string) =>
    request<{ checkout_url: string }>("/v2/billing/checkout", {
      method: "POST",
      token,
      body: { plan },
    }),

  // ---- team: members + invites ---- //

  listMembers: (token: string) =>
    request<{ members: Member[] }>("/v2/members", { token }),

  setMemberRole: (token: string, userId: string, role: string) =>
    request<{ user_id: string; role: string }>(
      `/v2/members/${encodeURIComponent(userId)}`,
      { method: "PATCH", token, body: { role } },
    ),

  removeMember: (token: string, userId: string) =>
    request<void>(`/v2/members/${encodeURIComponent(userId)}`, {
      method: "DELETE",
      token,
    }),

  listInvites: (token: string) =>
    request<{ invites: Invite[] }>("/v2/members/invites", { token }),

  createInvite: (token: string, email: string, role: string) =>
    request<NewInvite>("/v2/members/invites", {
      method: "POST",
      token,
      body: { email, role },
    }),

  revokeInvite: (token: string, inviteId: string) =>
    request<void>(`/v2/members/invites/${encodeURIComponent(inviteId)}`, {
      method: "DELETE",
      token,
    }),

  // Public — the invite token is the proof; no Bearer session required.
  acceptInvite: (inviteToken: string, password?: string, name?: string) =>
    request<TokenOut>("/v2/members/invites/accept", {
      method: "POST",
      body: { token: inviteToken, password, name },
    }),

  // ---- Wallet Guard ---- //

  guardCheck: (token: string, address: string, chain = "ethereum") =>
    request<GuardCheckResult>("/v2/guard/check", {
      method: "POST",
      token,
      body: { address, chain },
    }),

  listWatched: (token: string) =>
    request<{ addresses: WatchedAddress[] }>("/v2/guard/addresses", { token }),

  addWatched: (token: string, address: string, chain: string, label?: string) =>
    request<{ id: string; address: string; guard: GuardVerdict; alert_id: string | null }>(
      "/v2/guard/addresses",
      { method: "POST", token, body: { address, chain, label } },
    ),

  deleteWatched: (token: string, id: string) =>
    request<void>(`/v2/guard/addresses/${encodeURIComponent(id)}`, {
      method: "DELETE",
      token,
    }),

  listAlerts: (token: string, unacknowledged = false) =>
    request<{ alerts: WalletAlert[]; unacknowledged: number }>(
      `/v2/guard/alerts?unacknowledged=${unacknowledged ? 1 : 0}`,
      { token },
    ),

  ackAlert: (token: string, id: string) =>
    request<{ alert_id: string; acknowledged: boolean }>(
      `/v2/guard/alerts/${encodeURIComponent(id)}/ack`,
      { method: "POST", token },
    ),

  // ---- AI Assistant ---- //

  assistantChat: (
    token: string,
    messages: { role: "user" | "assistant"; content: string }[],
    chain = "ethereum",
  ) =>
    request<{ reply: string; grounded_addresses: string[]; model: string }>(
      "/v2/assistant/chat",
      { method: "POST", token, body: { messages, chain } },
    ),

  listAudit: (token: string, limit = 100) =>
    request<{ events: AuditEvent[] }>(`/v2/audit?limit=${limit}`, { token }),

  getArtifactUrl: (token: string, id: string, name: string) =>
    request<{ artifact: string; url: string; expires_in: number }>(
      `/v2/traces/${encodeURIComponent(id)}/artifacts/${encodeURIComponent(name)}`,
      { token },
    ),

  // Fund-flow graph as JSON ({nodes, edges, meta}) — same-origin, so a D3 view
  // can render it directly without opening the presigned interactive_graph.html
  // (avoids configuring CORS on the artifact bucket). 404 until the trace
  // completes; 503 if the graph can't be built.
  getGraph: (token: string, id: string) =>
    request<GraphData>(`/v2/traces/${encodeURIComponent(id)}/graph`, { token }),

  // SSE endpoint URL for live trace status. EventSource can't set headers, so
  // the session token rides as a query param (matches the server's /stream).
  streamUrl: (id: string, token: string) =>
    `${BASE_URL}/v2/traces/${encodeURIComponent(id)}/stream?token=${encodeURIComponent(token)}`,
};
