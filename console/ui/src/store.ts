import type { AssistanceSubjectKind, ServerMessage } from "@aisoc/shared";
import { DEFAULT_SETTINGS } from "@aisoc/shared";
import { create } from "zustand";
import { ensureSession, WS_URL } from "./lib/api";
import { applyServerMessage, type RemoteState } from "./lib/apply";

export type ViewId =
  | "overview"
  | "traffic"
  | "compass"
  | "dns"
  | "triage"
  | "incidents"
  | "assets"
  | "response"
  | "firewall"
  | "quarantine"
  | "llm"
  | "vpn"
  | "remoteaccess"
  | "reports"
  | "pentest"
  | "settings";

export type Toast = { id: number; level: "info" | "success" | "error"; message: string };

const LAYOUT_KEY = "aisoc.layout.v3";
const LEGACY_LAYOUT_KEYS = ["aisoc.layout.v2"];

type Layout = {
  view: ViewId;
  detailOpen: boolean;
  detailWidth: number;
  analyst: string;
  assistantOpen: boolean;
};

const defaultLayout: Layout = {
  view: "overview",
  detailOpen: true,
  detailWidth: 440,
  analyst: "analyst",
  assistantOpen: false,
};

const VIEW_IDS = new Set<ViewId>([
  "overview",
  "traffic",
  "compass",
  "dns",
  "triage",
  "incidents",
  "assets",
  "response",
  "firewall",
  "quarantine",
  "llm",
  "vpn",
  "remoteaccess",
  "reports",
  "pentest",
  "settings",
]);

function isViewId(v: string): v is ViewId {
  return VIEW_IDS.has(v as ViewId);
}

function loadLayout(): Layout {
  const hash = typeof window !== "undefined" ? window.location.hash.replace(/^#/, "") : "";
  const hashView = isViewId(hash) ? hash : undefined;
  for (const key of [LAYOUT_KEY, ...LEGACY_LAYOUT_KEYS]) {
    try {
      const raw = localStorage.getItem(key);
      if (raw) {
        const parsed = { ...defaultLayout, ...JSON.parse(raw) };
        if (hashView) parsed.view = hashView;
        return parsed;
      }
    } catch {
      // Fall through to the next key, then to defaults.
    }
  }
  return hashView ? { ...defaultLayout, view: hashView } : defaultLayout;
}

export type AssistantSubject = { kind: AssistanceSubjectKind; id: string };

/** Server-owned state is derived from the wire contract; only local state is declared here. */
type State = RemoteState & {
  connected: boolean;
  toasts: Toast[];

  view: ViewId;
  detailOpen: boolean;
  detailWidth: number;
  analyst: string;
  selectedEventId: string | null;
  selectedAlertId: string | null;
  selectedCallId: string | null;
  selectedIncidentId: string | null;
  selectedAssetId: string | null;
  severityFilter: number[];
  sourceFilter: string;
  textFilter: string;
  stageFilter: string;
  paused: boolean;
  notificationsOpen: boolean;
  terminalOpen: boolean;
  assistantOpen: boolean;
  assistantSubject: AssistantSubject | null;
  assistantChatId: string | null;

  setView: (view: ViewId) => void;
  setDetailOpen: (open: boolean) => void;
  setDetailWidth: (width: number) => void;
  setAnalyst: (name: string) => void;
  selectEvent: (id: string | null) => void;
  selectAlert: (id: string | null) => void;
  selectCall: (id: string | null) => void;
  selectIncident: (id: string | null) => void;
  selectAsset: (id: string | null) => void;
  toggleSeverity: (severity: number) => void;
  setSourceFilter: (value: string) => void;
  setTextFilter: (value: string) => void;
  setStageFilter: (value: string) => void;
  setFrozen: (frozen: boolean) => void;
  setNotificationsOpen: (open: boolean) => void;
  setTerminalOpen: (open: boolean) => void;
  openAssistant: (subject?: AssistantSubject) => void;
  closeAssistant: () => void;
  selectAssistantChat: (id: string | null) => void;
  pushToast: (level: Toast["level"], message: string) => void;
  dismissToast: (id: number) => void;
  apply: (message: ServerMessage) => void;
  setConnected: (connected: boolean) => void;
};

function persist(state: State): void {
  const layout: Layout = {
    view: state.view,
    detailOpen: state.detailOpen,
    detailWidth: state.detailWidth,
    analyst: state.analyst,
    assistantOpen: state.assistantOpen,
  };
  localStorage.setItem(LAYOUT_KEY, JSON.stringify(layout));
}

let toastSeq = 0;

export const useStore = create<State>((set, get) => ({
  connected: false,
  events: [],
  networkFlows: [],
  compass: null,
  compassReview: null,
  alerts: [],
  llmCalls: [],
  detections: [],
  pages: [],
  incidents: [],
  actions: [],
  assets: [],
  quarantine: [],
  lists: [],
  audit: [],
  notifications: [],
  rulePacks: [],
  playbooks: [],
  vpn: null,
  vpnServers: [],
  vpnProfiles: [],
  remoteAccess: null,
  stats: null,
  settings: DEFAULT_SETTINGS,
  secrets: {},
  toasts: [],

  ...loadLayout(),
  selectedEventId: null,
  selectedAlertId: null,
  selectedCallId: null,
  selectedIncidentId: null,
  selectedAssetId: null,
  severityFilter: [1, 2, 3, 4],
  sourceFilter: "",
  textFilter: "",
  stageFilter: "all",
  paused: false,
  notificationsOpen: false,
  terminalOpen: false,
  assistantSubject: null,
  assistantChatId: null,

  setView: (view) => {
    set({ view });
    persist(get());
  },
  setDetailOpen: (detailOpen) => {
    set({ detailOpen });
    persist(get());
  },
  setDetailWidth: (detailWidth) => {
    set({ detailWidth: Math.min(760, Math.max(320, detailWidth)) });
    persist(get());
  },
  setAnalyst: (analyst) => {
    set({ analyst });
    persist(get());
  },
  selectEvent: (selectedEventId) => set({ selectedEventId, detailOpen: true }),
  selectAlert: (selectedAlertId) => set({ selectedAlertId, detailOpen: true }),
  selectCall: (selectedCallId) => set({ selectedCallId }),
  selectIncident: (selectedIncidentId) => set({ selectedIncidentId }),
  selectAsset: (selectedAssetId) => set({ selectedAssetId }),
  toggleSeverity: (severity) =>
    set((state) => ({
      severityFilter: state.severityFilter.includes(severity)
        ? state.severityFilter.filter((s) => s !== severity)
        : [...state.severityFilter, severity].sort(),
    })),
  setSourceFilter: (sourceFilter) => set({ sourceFilter }),
  setTextFilter: (textFilter) => set({ textFilter }),
  setStageFilter: (stageFilter) => set({ stageFilter }),
  setFrozen: (paused) => set({ paused }),
  setNotificationsOpen: (notificationsOpen) => set({ notificationsOpen }),
  setTerminalOpen: (terminalOpen) => set({ terminalOpen }),
  openAssistant: (subject) => {
    set({ assistantOpen: true, assistantSubject: subject ?? null, assistantChatId: null });
    persist(get());
  },
  closeAssistant: () => {
    set({ assistantOpen: false });
    persist(get());
  },
  selectAssistantChat: (assistantChatId) => set({ assistantChatId }),
  pushToast: (level, message) => {
    const id = ++toastSeq;
    set((state) => ({ toasts: [...state.toasts, { id, level, message }] }));
    setTimeout(() => get().dismissToast(id), 6_000);
  },
  dismissToast: (id) => set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) })),
  setConnected: (connected) => set({ connected }),

  apply: (message) => {
    if (message.type === "toast") {
      get().pushToast(message.level, message.message);
      return;
    }
    set((state) => applyServerMessage(state, message));
  },
}));

export function connect(): void {
  let socket: WebSocket | null = null;
  let retry = 500;

  const open = async () => {
    try {
      // A backend restart invalidates its in-memory sessions. Bootstrap on
      // every socket reconnect so the UI recovers instead of retrying a stale
      // cookie forever.
      await ensureSession(true);
    } catch {
      useStore.getState().setConnected(false);
      setTimeout(open, retry);
      retry = Math.min(5_000, retry * 2);
      return;
    }
    socket = new WebSocket(WS_URL);
    socket.onopen = () => {
      retry = 500;
      useStore.getState().setConnected(true);
    };
    socket.onmessage = (event) => {
      try {
        useStore.getState().apply(JSON.parse(event.data) as ServerMessage);
      } catch {
        // Ignore anything that isn't a well-formed server message.
      }
    };
    socket.onclose = () => {
      useStore.getState().setConnected(false);
      setTimeout(open, retry);
      retry = Math.min(5_000, retry * 2);
    };
    socket.onerror = () => socket?.close();
  };

  open();
}
