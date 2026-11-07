import type {
  AnalystChatModelOption,
  AssistanceChat,
  AssistanceSubjectKind,
  CompassReview,
  CompassSummary,
  DnsSummary,
  ExportKind,
  MitreRef,
  PentestProfile,
  PentestRun,
  PentestTarget,
  RemoteAccessState,
  Report,
  ResponseType,
  Severity,
  VpnCheck,
  VpnConnection,
  VpnProfile,
  VpnServer,
} from "@aisoc/shared";

const BASE =
  import.meta.env.VITE_AISOC_API ??
  (typeof window !== "undefined" && window.location.origin.startsWith("http")
    ? window.location.origin
    : "http://127.0.0.1:4319");

export const WS_URL = `${BASE.replace(/^http/, "ws")}/ws`;

export const pentestWsUrl = (runId: string): string =>
  `${BASE.replace(/^http/, "ws")}/ws/pentest?runId=${encodeURIComponent(runId)}`;

let csrf = "";
let sessionRequest: Promise<void> | null = null;

export function ensureSession(force = false): Promise<void> {
  if (force) csrf = "";
  if (csrf) return Promise.resolve();
  if (!sessionRequest) {
    sessionRequest = fetch(`${BASE}/api/session`, { credentials: "include" })
      .then(async (response) => {
        const body = (await response.json().catch(() => ({}))) as { csrf?: string; error?: string };
        if (!response.ok || !body.csrf) throw new Error(body.error ?? "session bootstrap failed");
        csrf = body.csrf;
      })
      .finally(() => {
        sessionRequest = null;
      });
  }
  return sessionRequest;
}

async function sessionFetch(path: string, init?: RequestInit, retry = true): Promise<Response> {
  await ensureSession();
  const headers = new Headers(init?.headers);
  if ((init?.method ?? "GET") !== "GET") headers.set("x-csrf-token", csrf);
  const response = await fetch(`${BASE}${path}`, {
    ...init,
    headers,
    credentials: "include",
  });
  if (response.status === 401 && retry) {
    await ensureSession(true);
    return sessionFetch(path, init, false);
  }
  return response;
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const response = await sessionFetch(path, {
    method: "POST",
    // Fastify rejects an empty body when content-type says JSON, so omit both.
    headers: {
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error((json as { error?: string }).error ?? response.statusText);
  return json as T;
}

async function get<T>(path: string): Promise<T> {
  await ensureSession();
  const response = await sessionFetch(path);
  if (!response.ok) throw new Error(response.statusText);
  return (await response.json()) as T;
}

async function del<T>(path: string): Promise<T> {
  const response = await sessionFetch(path, { method: "DELETE" });
  const json = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error((json as { error?: string }).error ?? response.statusText);
  return json as T;
}

export interface RuleSummary {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  score: number;
  confidence: number;
  origin: string;
  mitre: MitreRef[];
}

export interface ScenarioSummary {
  id: string;
  name: string;
  description: string;
  steps: number;
}

/** Exports stream straight from the backend, so the browser handles the download. */
export function exportUrl(kind: ExportKind, format: "csv" | "json"): string {
  return `${BASE}/api/export/${kind}?format=${format}`;
}

export const api = {
  saveSettings: (patch: unknown) => post("/api/settings", patch),
  saveSecret: (name: string, value: string) => post("/api/secrets", { name, value }),
  testTelegram: () => post<{ ok: boolean; error?: string }>("/api/telegram/test"),
  testSmtp: (to: string) => post<{ ok: boolean; error?: string }>("/api/smtp/test", { to }),
  compass: () => get<{ ok: boolean; summary: CompassSummary }>("/api/compass"),
  dns: () => get<{ ok: boolean; summary: DnsSummary }>("/api/dns"),
  dnsBlocking: (enabled: boolean) =>
    post<{ ok: boolean; error?: string }>("/api/dns/blocking", { enabled }),
  reviewCompass: () =>
    post<{ ok: boolean; review: CompassReview; error?: string }>("/api/compass/review"),
  forgetCompass: () => post<{ ok: boolean; summary: CompassSummary }>("/api/compass/forget"),
  compassFeedback: (id: string, status: "dismissed" | "snoozed") =>
    post<{ ok: boolean; summary: CompassSummary }>("/api/compass/feedback", { id, status }),
  assistanceModels: () =>
    get<{ ok: boolean; models: AnalystChatModelOption[] }>("/api/assistant/chat/models"),
  assistanceAllChats: () => get<{ ok: boolean; chats: AssistanceChat[] }>("/api/assistant/chat"),
  sendAssistanceMessage: (
    chatId: string | null,
    subjectKind: AssistanceSubjectKind,
    subjectId: string,
    message: string,
    model: string,
  ) =>
    post<{ ok: boolean; chat: AssistanceChat }>(
      chatId ? `/api/assistant/chat/${chatId}` : "/api/assistant/chat",
      { subjectKind, subjectId, message, model },
    ),
  deleteAssistanceChat: (id: string) => del<{ ok: boolean }>(`/api/assistant/chat/${id}`),

  override: (id: string, verdict: string, by: string, note: string) =>
    post(`/api/alerts/${id}/override`, { verdict, by, note }),
  comment: (id: string, author: string, body: string) =>
    post(`/api/alerts/${id}/comment`, { author, body }),
  requeue: (id: string) => post(`/api/alerts/${id}/requeue`),

  createAction: (input: {
    alertId: string | null;
    type: ResponseType;
    target: string;
    reason: string;
    by: string;
  }) => post("/api/actions", input),
  approveAction: (id: string, by: string) => post(`/api/actions/${id}/approve`, { by }),
  rejectAction: (id: string, by: string) => post(`/api/actions/${id}/reject`, { by }),
  undoAction: (id: string, by: string) => post(`/api/actions/${id}/undo`, { by }),

  setIncidentStatus: (id: string, status: string, by: string) =>
    post(`/api/incidents/${id}/status`, { status, by }),
  assignIncident: (id: string, assignee: string, by: string) =>
    post(`/api/incidents/${id}/assign`, { assignee, by }),
  incidentNote: (id: string, author: string, body: string) =>
    post(`/api/incidents/${id}/note`, { author, body }),
  narrateIncident: (id: string) => post(`/api/incidents/${id}/narrate`),

  isolateAsset: (id: string, isolated: boolean, by: string) =>
    post(`/api/assets/${id}/isolate`, { isolated, by }),

  restoreQuarantine: (id: string, by: string) => post(`/api/quarantine/${id}/restore`, { by }),
  deleteQuarantine: (id: string, by: string) => post(`/api/quarantine/${id}/delete`, { by }),

  addListEntry: (input: {
    list: "allow" | "block";
    kind: string;
    value: string;
    note: string;
    by: string;
  }) => post("/api/lists", { ...input, expiresAt: null }),
  removeListEntry: (id: string, by: string) => post(`/api/lists/${id}/remove`, { by }),

  markNotificationsRead: (ids: string[] | null) =>
    post<{ ids: string[] }>("/api/notifications/read", ids ? { ids } : {}),

  firewall: () =>
    get<{
      ok: boolean;
      error?: string;
      blocked: { ip: string; set: string; timeout: number | null; expires: number | null }[];
      protected: string[];
      blocksLastHour: number;
      maxBlocksPerHour: number;
    }>("/api/firewall"),
  firewallUnblock: (ip: string) => post("/api/firewall/unblock", { ip }),

  report: (period: "daily" | "weekly") => get<Report>(`/api/reports?period=${period}`),
  rules: () => get<RuleSummary[]>("/api/detection/rules"),
  scenarios: () => get<ScenarioSummary[]>("/api/scenarios"),

  updateRulePacks: () => post("/api/rulepacks/update"),
  toggleRulePack: (id: string) => post(`/api/rulepacks/${id}/toggle`),
  togglePlaybook: (id: string) => post(`/api/playbooks/${id}/toggle`),

  vpnServers: () => get<VpnServer[]>("/api/vpn/servers"),
  vpnConfig: (target: { serverId?: string | null; profileId?: string | null }) => {
    const query = new URLSearchParams();
    if (target.serverId) query.set("serverId", target.serverId);
    if (target.profileId) query.set("profileId", target.profileId);
    const suffix = query.toString();
    return get<{ config: string }>(`/api/vpn/config${suffix ? `?${suffix}` : ""}`);
  },
  vpnPreflight: () => get<VpnCheck[]>("/api/vpn/preflight"),
  vpnImport: (input: { config: string; source: string; name: string; by: string }) =>
    post<{ profile: VpnProfile; warnings: string[] }>("/api/vpn/profiles", input),
  vpnRemoveProfile: (id: string, by: string) => post(`/api/vpn/profiles/${id}/remove`, { by }),
  vpnConnect: (target: { serverId?: string | null; profileId?: string | null }, by: string) =>
    post<{ connection: VpnConnection }>("/api/vpn/connect", {
      serverId: target.serverId ?? null,
      profileId: target.profileId ?? null,
      by,
    }),
  vpnDisconnect: (by: string) => post<{ connection: VpnConnection }>("/api/vpn/disconnect", { by }),

  remoteAccessPreflight: () => get<VpnCheck[]>("/api/remoteaccess/preflight"),
  remoteAccessUp: () => post<{ ok: boolean; state: RemoteAccessState }>("/api/remoteaccess/up"),
  remoteAccessDown: () => post<{ ok: boolean; state: RemoteAccessState }>("/api/remoteaccess/down"),

  fireScenario: (id: string) => post(`/api/scenarios/${id}/fire`),
  ack: (id: string, by: string) => post(`/api/incidents/${id}/ack`, { by }),
  pause: () => post("/api/control/pause"),
  resume: () => post("/api/control/resume"),
  oncallDrill: () => post<{ ok: boolean; alertId?: string }>("/api/oncall/drill"),

  pentestRuns: () => get<{ ok: boolean; runs: PentestRun[] }>("/api/pentest/runs"),
  pentestTargets: () => get<{ ok: boolean; targets: PentestTarget[] }>("/api/pentest/targets"),
  startPentest: (target: string, profile: PentestProfile) =>
    post<{ ok: boolean; run: PentestRun }>("/api/pentest/run", { target, profile }),
  cancelPentest: (id: string) => post<{ ok: boolean }>(`/api/pentest/runs/${id}/cancel`),

  services: () =>
    get<{
      ok: boolean;
      groups: {
        title: string;
        services: { name: string; label: string; kind: string; active: boolean }[];
      }[];
    }>("/api/services"),
  serviceAction: (name: string, action: string) =>
    post<{ ok: boolean; output?: string; error?: string }>(
      `/api/services/${encodeURIComponent(name)}/${action}`,
    ),
};
