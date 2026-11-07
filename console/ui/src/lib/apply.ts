import type { Alert, Asset, AuditEntry, ServerMessage, Snapshot } from "@aisoc/shared";

/**
 * The live stream reduced to state, kept apart from the store so it is a plain
 * function of (state, message) rather than something only a mounted app can
 * exercise. Everything the console shows after the opening snapshot arrives
 * through here, so its retention caps and identity rules are the behaviour most
 * worth testing.
 */

/** The four the server always sends but the client has not received yet on first paint. */
export type PendingUntilSnapshot = "compass" | "vpn" | "remoteAccess" | "stats";

/**
 * Everything the server owns, shaped exactly like the payload that fills it — a
 * new `Snapshot` field is a type error here rather than a silently missing one.
 */
export type RemoteState = Omit<Snapshot, PendingUntilSnapshot> & {
  [K in PendingUntilSnapshot]: Snapshot[K] | null;
};

/** Local state the reducer reads: a frozen view drops events, and a cleared call deselects. */
export type StreamState = RemoteState & {
  paused: boolean;
  selectedCallId: string | null;
};

/**
 * Client-side retention. The server keeps far more; these are what a browser
 * tab can hold without the table components degrading.
 */
const MAX_EVENTS = 800;
const MAX_DETECTIONS = 600;
const MAX_FLOWS = 1_000;
const MAX_AUDIT = 1_000;
const MAX_NOTIFICATIONS = 300;

/** Replace-or-append by id, keeping the array identity stable when nothing changed. */
export function upsert<T extends { id: string }>(list: T[], item: T): T[] {
  const index = list.findIndex((entry) => entry.id === item.id);
  if (index === -1) return [...list, item];
  const next = list.slice();
  next[index] = item;
  return next;
}

function capped<T>(list: T[], max: number): T[] {
  return list.length > max ? list.slice(-max) : list;
}

/**
 * `toast` is the one message with no state of its own, so the store handles it
 * before delegating and the reducer never sees it.
 */
export function applyServerMessage(
  state: StreamState,
  message: Exclude<ServerMessage, { type: "toast" }>,
): Partial<StreamState> {
  switch (message.type) {
    case "snapshot": {
      const { type: _snapshot, ...remote } = message;
      return remote;
    }
    // A frozen view is a held reading, not a paused stream: everything else
    // keeps updating so the rest of the console stays truthful.
    case "event":
      return state.paused ? {} : { events: capped([...state.events, message.event], MAX_EVENTS) };
    case "network-flow":
      return { networkFlows: capped(upsert(state.networkFlows, message.flow), MAX_FLOWS) };
    case "compass":
      return { compass: message.summary };
    case "compass-review":
      return { compassReview: message.review };
    case "alert":
      return { alerts: upsert(state.alerts, message.alert) };
    case "llm":
      return { llmCalls: upsert(state.llmCalls, message.call) };
    case "llm-clear": {
      const cleared = state.llmCalls.some(
        (call) => call.id === state.selectedCallId && message.stages.includes(call.stage),
      );
      return {
        llmCalls: state.llmCalls.filter((call) => !message.stages.includes(call.stage)),
        selectedCallId: cleared ? null : state.selectedCallId,
      };
    }
    case "detection":
      return { detections: capped(upsert(state.detections, message.detection), MAX_DETECTIONS) };
    case "page":
      return { pages: upsert(state.pages, message.page) };
    case "incident":
      return { incidents: upsert(state.incidents, message.incident) };
    case "action":
      return { actions: upsert(state.actions, message.action) };
    case "asset":
      return { assets: upsert(state.assets, message.asset) };
    case "quarantine":
      return { quarantine: upsert(state.quarantine, message.item) };
    case "lists":
      return { lists: message.entries };
    case "audit":
      return { audit: capped([...state.audit, message.entry], MAX_AUDIT) };
    case "notification":
      return {
        notifications: capped([...state.notifications, message.notification], MAX_NOTIFICATIONS),
      };
    case "notifications-read": {
      const read = new Set(message.ids);
      return {
        notifications: state.notifications.map((entry) =>
          read.has(entry.id) ? { ...entry, read: true } : entry,
        ),
      };
    }
    case "rulePacks":
      return { rulePacks: message.packs };
    case "playbooks":
      return { playbooks: message.playbooks };
    case "vpn":
      return {
        vpn: message.connection,
        vpnServers: message.servers,
        vpnProfiles: message.profiles,
      };
    case "remoteaccess":
      return { remoteAccess: message.state };
    case "stats":
      return { stats: message.stats };
    case "settings":
      return { settings: message.settings, secrets: message.secrets };
    default:
      return {};
  }
}

export type { Alert, Asset, AuditEntry };
