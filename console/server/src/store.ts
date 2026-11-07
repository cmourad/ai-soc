import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import type {
  Alert,
  Asset,
  AuditEntry,
  DetectionRun,
  Incident,
  ListEntry,
  LlmCall,
  Notification,
  OncallIncident,
  Playbook,
  QuarantineItem,
  RemoteAccessState,
  ResponseAction,
  RulePack,
  SecurityEvent,
  VpnConnection,
  VpnProfile,
} from "@aisoc/shared";
import { blankRemoteAccessState } from "@aisoc/shared";
import { writePrivateAtomic } from "./atomic.js";
import { broadcast } from "./bus.js";
import {
  countDetectionRun,
  countEvent,
  countLlmCall,
  countLlmError,
  countTokens,
} from "./metrics.js";
import { STATE_FILE } from "./paths.js";
import { getSettings } from "./settings.js";

const MAX_EVENTS = 2_000;
const MAX_LLM_CALLS = 500;
const MAX_DETECTIONS = 1_000;
const MAX_ALERTS = 2_000;
const MAX_PAGES = 200;
const MAX_INCIDENTS = 500;
const MAX_ACTIONS = 1_000;
const MAX_AUDIT = 5_000;
const MAX_NOTIFICATIONS = 300;

const events: SecurityEvent[] = [];
const alerts = new Map<string, Alert>();
const llmCalls = new Map<string, LlmCall>();
const detections: DetectionRun[] = [];
const pages = new Map<string, OncallIncident>();
const incidents = new Map<string, Incident>();
const actions = new Map<string, ResponseAction>();
const assets = new Map<string, Asset>();
const quarantine = new Map<string, QuarantineItem>();
const lists = new Map<string, ListEntry>();
const audit: AuditEntry[] = [];
const notifications: Notification[] = [];
/** Seeded by `restore` from composition; feature defaults are not the store's to know. */
let rulePacks: RulePack[] = [];
/**
 * Tunnel state lives here rather than in the manager so the snapshot, the stats
 * gauge, and the response guardrails all read one source of truth.
 */
let vpnProfiles: VpnProfile[] = [];
let vpn: VpnConnection = {
  status: "disconnected",
  serverId: null,
  profileId: null,
  tunnelIp: null,
  exitIp: null,
  interfaceName: "aisoc0",
  connectedAt: null,
  lastHandshake: null,
  bytesUp: 0,
  bytesDown: 0,
  simulated: true,
  killSwitchEngaged: false,
  error: null,
};
let playbooks: Playbook[] = [];

let remoteAccess: RemoteAccessState = blankRemoteAccessState();

let incidentSequence = 0;

/**
 * Where a notification goes once it exists. Recording one is a state change;
 * pushing it to Telegram is delivery, and the store must not reach outward from
 * inside a mutation. Composition installs the real sink at startup.
 */
let notificationSink: (notification: Notification) => void = () => {};

export function registerNotificationSink(sink: typeof notificationSink): void {
  notificationSink = sink;
}

export function addEvent(event: SecurityEvent): void {
  events.push(event);
  if (events.length > MAX_EVENTS) events.splice(0, events.length - MAX_EVENTS);
  countEvent();
  broadcast({ type: "event", event });
}

export function listEvents(): SecurityEvent[] {
  return events;
}

export function upsertAlert(alert: Alert): void {
  alert.updatedAt = new Date().toISOString();
  alerts.set(alert.id, alert);
  if (alerts.size > MAX_ALERTS) {
    const oldest = [...alerts.values()]
      .filter((a) => a.stage === "resolved")
      .sort((a, b) => a.updatedAt.localeCompare(b.updatedAt))[0];
    if (oldest) alerts.delete(oldest.id);
  }
  broadcast({ type: "alert", alert });
  persistSoon();
}

export function getAlert(id: string): Alert | undefined {
  return alerts.get(id);
}

export function listAlerts(): Alert[] {
  return [...alerts.values()];
}

export function upsertLlmCall(call: LlmCall): void {
  // The caller mutates and re-submits the same object, so the map must hold a
  // snapshot — otherwise `previous` and `call` are the same reference and every
  // transition looks like a no-op.
  const previous = llmCalls.get(call.id);
  llmCalls.set(call.id, { ...call });
  if (!previous) countLlmCall();

  // Count transitions, not writes: a call is upserted several times as it runs.
  const failed = call.status === "error" || call.status === "timeout";
  const wasFailed = previous?.status === "error" || previous?.status === "timeout";
  if (failed && !wasFailed) countLlmError();
  if (call.tokens && !previous?.tokens) countTokens(call.tokens.total);
  if (llmCalls.size > MAX_LLM_CALLS) {
    const oldest = [...llmCalls.values()].sort((a, b) => a.startedAt.localeCompare(b.startedAt))[0];
    if (oldest) llmCalls.delete(oldest.id);
  }
  broadcast({ type: "llm", call });
}

export function listLlmCalls(): LlmCall[] {
  return [...llmCalls.values()];
}

/** Remove model records whose prompts contain Compass site data. */
export function clearCompassLlmCalls(): void {
  const stages = ["compass_review", "compass_chat"] as const;
  for (const [id, call] of llmCalls) {
    if (stages.includes(call.stage as (typeof stages)[number])) llmCalls.delete(id);
  }
  broadcast({ type: "llm-clear", stages: [...stages] });
}

export function addDetectionRun(run: DetectionRun): void {
  detections.push(run);
  countDetectionRun(run.hits.length);
  if (detections.length > MAX_DETECTIONS) detections.splice(0, detections.length - MAX_DETECTIONS);
  broadcast({ type: "detection", detection: run });
}

export function listDetections(): DetectionRun[] {
  return detections;
}

/** Back-fills the alert id once the event that produced this run became an alert. */
export function linkDetectionToAlert(eventId: string, alertId: string): void {
  const run = detections.findLast((entry) => entry.eventId === eventId);
  if (!run || run.alertId) return;
  run.alertId = alertId;
  broadcast({ type: "detection", detection: run });
}

export function upsertPage(page: OncallIncident): void {
  pages.set(page.id, page);
  if (pages.size > MAX_PAGES) {
    const oldest = [...pages.values()].sort((a, b) => a.createdAt.localeCompare(b.createdAt))[0];
    if (oldest) pages.delete(oldest.id);
  }
  broadcast({ type: "page", page });
  persistSoon();
}

export function getPage(id: string): OncallIncident | undefined {
  return pages.get(id);
}

export function listPages(): OncallIncident[] {
  return [...pages.values()];
}

export function upsertIncident(incident: Incident): void {
  incident.updatedAt = new Date().toISOString();
  incidents.set(incident.id, incident);
  if (incidents.size > MAX_INCIDENTS) {
    const oldest = [...incidents.values()]
      .filter((entry) => entry.status === "closed")
      .sort((a, b) => a.updatedAt.localeCompare(b.updatedAt))[0];
    if (oldest) incidents.delete(oldest.id);
  }
  broadcast({ type: "incident", incident });
  persistSoon();
}

export function getIncident(id: string): Incident | undefined {
  return incidents.get(id);
}

export function listIncidents(): Incident[] {
  return [...incidents.values()];
}

export function nextIncidentRef(): string {
  incidentSequence += 1;
  return `INC-${String(incidentSequence).padStart(4, "0")}`;
}

export function upsertAction(action: ResponseAction): void {
  actions.set(action.id, action);
  if (actions.size > MAX_ACTIONS) {
    const oldest = [...actions.values()].sort((a, b) => a.createdAt.localeCompare(b.createdAt))[0];
    if (oldest) actions.delete(oldest.id);
  }
  broadcast({ type: "action", action });
  persistSoon();
}

export function getAction(id: string): ResponseAction | undefined {
  return actions.get(id);
}

export function listActions(): ResponseAction[] {
  return [...actions.values()];
}

export function upsertAsset(asset: Asset): void {
  assets.set(asset.id, asset);
  broadcast({ type: "asset", asset });
  persistSoon();
}

export function getAsset(id: string): Asset | undefined {
  return assets.get(id);
}

export function listAssets(): Asset[] {
  return [...assets.values()];
}

export function upsertQuarantine(item: QuarantineItem): void {
  quarantine.set(item.id, item);
  broadcast({ type: "quarantine", item });
  persistSoon();
}

export function getQuarantine(id: string): QuarantineItem | undefined {
  return quarantine.get(id);
}

export function listQuarantine(): QuarantineItem[] {
  return [...quarantine.values()];
}

export function setListEntries(entries: ListEntry[]): void {
  lists.clear();
  for (const entry of entries) lists.set(entry.id, entry);
  broadcast({ type: "lists", entries: listListEntries() });
  persistSoon();
}

export function listListEntries(): ListEntry[] {
  return [...lists.values()];
}

export function addAudit(
  actor: string,
  action: string,
  target: string,
  detail: string,
  ok = true,
): AuditEntry {
  const entry: AuditEntry = {
    id: randomUUID(),
    at: new Date().toISOString(),
    actor,
    action,
    target,
    detail,
    ok,
  };
  audit.push(entry);
  if (audit.length > MAX_AUDIT) audit.splice(0, audit.length - MAX_AUDIT);
  broadcast({ type: "audit", entry });
  persistSoon();
  return entry;
}

export function listAudit(): AuditEntry[] {
  return audit;
}

export function addNotification(
  notification: Omit<Notification, "id" | "at" | "read">,
): Notification | null {
  const settings = getSettings();
  if (!settings.notifications[notification.kind]) return null;
  const full: Notification = {
    ...notification,
    id: randomUUID(),
    at: new Date().toISOString(),
    read: false,
  };
  notifications.push(full);
  if (notifications.length > MAX_NOTIFICATIONS) {
    notifications.splice(0, notifications.length - MAX_NOTIFICATIONS);
  }
  broadcast({ type: "notification", notification: full });
  notificationSink(full);
  return full;
}

export function markNotificationsRead(ids: string[] | null): string[] {
  const target = ids ? new Set(ids) : null;
  const changed: string[] = [];
  for (const notification of notifications) {
    if (notification.read) continue;
    if (target && !target.has(notification.id)) continue;
    notification.read = true;
    changed.push(notification.id);
  }
  if (changed.length > 0) broadcast({ type: "notifications-read", ids: changed });
  return changed;
}

export function listNotifications(): Notification[] {
  return notifications;
}

export function listRulePacks(): RulePack[] {
  return rulePacks;
}

export function setRulePacks(packs: RulePack[]): void {
  rulePacks = packs;
  broadcast({ type: "rulePacks", packs });
  persistSoon();
}

export function listPlaybooks(): Playbook[] {
  return playbooks;
}

export function setPlaybooks(next: Playbook[]): void {
  playbooks = next;
  broadcast({ type: "playbooks", playbooks: next });
  persistSoon();
}

export function getVpn(): VpnConnection {
  return vpn;
}

export function setVpn(next: VpnConnection): void {
  vpn = next;
}

export function listVpnProfiles(): VpnProfile[] {
  return vpnProfiles;
}

export function setVpnProfiles(next: VpnProfile[]): void {
  vpnProfiles = next;
  persistSoon();
}

export function getRemoteAccess(): RemoteAccessState {
  return remoteAccess;
}

export function setRemoteAccess(next: RemoteAccessState): void {
  remoteAccess = next;
  broadcast({ type: "remoteaccess", state: next });
}

let persistTimer: NodeJS.Timeout | null = null;

function persistSoon(): void {
  if (persistTimer) return;
  persistTimer = setTimeout(() => {
    persistTimer = null;
    // tmp + rename: the previous in-place write left a half-written 640 KB file
    // if the process died mid-flush, and restore() discards a file it cannot
    // parse — one crash at the wrong instant lost all alerts, incidents and
    // actions. rename(2) within a directory is atomic, so a reader sees either
    // the old state or the new one.
    writePrivateAtomic(
      STATE_FILE,
      JSON.stringify({
        alerts: listAlerts(),
        pages: listPages(),
        incidents: listIncidents(),
        incidentSequence,
        actions: listActions(),
        assets: listAssets(),
        quarantine: listQuarantine(),
        lists: listListEntries(),
        audit: audit.slice(-2_000),
        rulePacks,
        playbooks,
        vpnProfiles,
      }),
    );
  }, 2_000);
}

/**
 * Events written before the byte counters were split carry one `bytes` total
 * with no way to recover which direction it went. Attributing it to egress is
 * what produced the false exfiltration incidents in the first place, so a
 * legacy total counts as inbound: a re-triaged historical alert then understates
 * egress rather than inventing it.
 */
function migrateBytes(event: SecurityEvent & { bytes?: number }): void {
  if (typeof event.bytesToServer === "number") return;
  event.bytesToServer = 0;
  event.bytesToClient = event.bytes ?? 0;
  delete event.bytes;
}

/**
 * Seeds are handed in rather than imported: which rule packs and playbooks ship
 * by default is a feature decision, and persisted state overrides them.
 */
export function restore(seed: { rulePacks: RulePack[]; playbooks: Playbook[] }): void {
  rulePacks = seed.rulePacks;
  playbooks = seed.playbooks;
  if (!existsSync(STATE_FILE)) return;
  try {
    const state = JSON.parse(readFileSync(STATE_FILE, "utf8"));
    for (const alert of (state.alerts ?? []) as Alert[]) {
      alert.origin ??= "event";
      migrateBytes(alert.event);
      // Nothing is driving an alert that was mid-flight when we stopped. Leaving
      // it in a working stage would strand it forever with no job behind it, so
      // it lands in front of a human instead — and is re-runnable from the UI.
      if (alert.stage !== "resolved" && alert.stage !== "needs_human") {
        alert.notes.push({
          id: randomUUID(),
          at: new Date().toISOString(),
          author: "pipeline",
          kind: "system",
          body: `Triage was in progress (${alert.stage.replace(/_/g, " ")}) when the backend restarted — routed to a human.`,
        });
        alert.stage = "needs_human";
        alert.verdict = alert.verdict ?? "WATCH";
      }
      alerts.set(alert.id, alert);
    }
    // `incidents` used to hold on-call pages; anything under the old key is one.
    for (const page of (state.pages ?? state.incidents ?? []) as OncallIncident[]) {
      if ("alertId" in page && "rotation" in page) pages.set(page.id, page);
    }
    for (const incident of (state.incidents ?? []) as Incident[]) {
      if ("ref" in incident) incidents.set(incident.id, incident);
    }
    incidentSequence = state.incidentSequence ?? incidents.size;
    for (const action of (state.actions ?? []) as ResponseAction[]) actions.set(action.id, action);
    for (const asset of (state.assets ?? []) as Asset[]) assets.set(asset.id, asset);
    for (const item of (state.quarantine ?? []) as QuarantineItem[]) quarantine.set(item.id, item);
    for (const entry of (state.lists ?? []) as ListEntry[]) lists.set(entry.id, entry);
    audit.push(...((state.audit ?? []) as AuditEntry[]));
    if (Array.isArray(state.rulePacks) && state.rulePacks.length > 0) rulePacks = state.rulePacks;
    if (Array.isArray(state.playbooks) && state.playbooks.length > 0) playbooks = state.playbooks;
    if (Array.isArray(state.vpnProfiles)) vpnProfiles = state.vpnProfiles;
  } catch {
    // A corrupt state file is not worth failing startup over.
  }
}
