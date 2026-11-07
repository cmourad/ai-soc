Technical reference: Static analysis and code architecture audit report.

# Code Scan Report
- Root: /opt/aisoc
- Date: 2026-08-18
- Files scanned: 138 · LOC: 35528 · Packages: agent, scripts, console/desktop, console/server, console/shared, console/ui, deployment/config
- Architecture model: Inferred as a layered workstation-security system: `console/shared` owns dependency-free domain types and pure network/flow helpers; `console/server` contains composition, application features, and infrastructure; `console/ui` is presentation consuming the shared contract and server API; `agent` and privileged helper scripts form separate host-process boundaries. Within the server, the entrypoint should compose feature modules, while state/persistence/settings remain lower-level dependencies and should not call feature delivery or policy modules.

## 1. Executive summary
- Totals by severity: critical 3 · high 4 · medium 9 · low 7 · info 2
- Duplicated lines (estimate): 330 (0.9% of LOC)
- Top 5 risks:
  - DUP-003-001: three implementations of the framed privileged-helper protocol already disagree on valid fragmented input.
  - DUP-003-002: byte quantities use incompatible decimal and binary formatting rules.
  - ARCH-001-001: the central state layer imports feature policy and directly performs notification delivery.
  - ARCH-002-001: the shared package barrel participates in a type-level import cycle.
  - DUP-003-004: security-sensitive HTML escaping is independently maintained in two notification paths.

## 2. Findings

### DUP-003 — Duplicate logic (5 findings, suppressed: 0)

#### DUP-003-001 · Privileged-helper framing protocol has divergent implementations · severity: critical · confidence: high
- Locations: `agent/aisoc.py:467-489`, `agent/process_helper.py:24-44`, `scripts/vpn-helper.py:10-24`
- Duplicated behavior: Encode and decode JSON messages using a four-byte network-order length prefix with an 8192-byte limit.
- Divergence: yes — the agent and process helper read the four-byte header exactly, while the VPN helper calls `recv(4)` once and rejects a valid header split across stream packets.
- Evidence:
  ```py
  # agent/aisoc.py:467-476
  def _read_exact(conn, size):
      chunks = []
      remaining = size
      while remaining:
          chunk = conn.recv(remaining)
          if not chunk:
              raise ValueError("connection closed mid-frame")
  ```
  ```py
  # agent/process_helper.py:35-44
  def read_frame(conn):
      size = struct.unpack("!I", _read_exact(conn, 4))[0]
      if not 1 <= size <= MAX_FRAME:
          raise ValueError("invalid frame length")
      return json.loads(_read_exact(conn, size))
  ```
  ```py
  # scripts/vpn-helper.py:14-23
  def read_frame(conn):
      head = conn.recv(4)
      if len(head) != 4: raise ValueError("missing frame")
      size = struct.unpack("!I", head)[0]
      if not 1 <= size <= 8192: raise ValueError("invalid frame length")
  ```
- Impact: A valid VPN control request can fail nondeterministically depending on Unix-stream packetization, and future protocol changes must be synchronized manually.
- Recommended fix: Centralize Python framing and exact-read behavior in one importable IPC helper, then make every privileged boundary use it.
- Effort: M

#### DUP-003-002 · Byte formatting rules disagree across the product · severity: critical · confidence: high
- Locations: `console/server/src/network/compass.ts:439-444`, `console/ui/src/views/NetworkCompass.tsx:48-53`, `console/ui/src/lib/utils.ts:125-130`
- Duplicated behavior: Convert byte counts to human-readable B/KB/MB/GB strings.
- Divergence: yes — Compass uses binary divisors and `KB`, while the shared UI helper uses decimal divisors and `kB`, yielding different values for the same input.
- Evidence:
  ```ts
  // console/server/src/network/compass.ts:439-444
  function bytesText(value: number): string {
    if (value < 1_024) return `${value} B`;
    if (value < 1_048_576) return `${(value / 1_024).toFixed(1)} KB`;
    if (value < 1_073_741_824) return `${(value / 1_048_576).toFixed(1)} MB`;
    return `${(value / 1_073_741_824).toFixed(2)} GB`;
  }
  ```
  ```ts
  // console/ui/src/views/NetworkCompass.tsx:48-53
  function bytes(value: number): string {
    if (value < 1_024) return `${value} B`;
    if (value < 1_048_576) return `${(value / 1_024).toFixed(1)} KB`;
    if (value < 1_073_741_824) return `${(value / 1_048_576).toFixed(1)} MB`;
    return `${(value / 1_073_741_824).toFixed(2)} GB`;
  }
  ```
  ```ts
  // console/ui/src/lib/utils.ts:125-130
  export function bytes(value: number): string {
    if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(1)} GB`;
    if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)} MB`;
    if (value >= 1_000) return `${(value / 1_000).toFixed(1)} kB`;
    return `${value} B`;
  }
  ```
- Impact: Identical traffic totals are displayed differently between screens and server-generated insight text.
- Recommended fix: Select one explicit SI or IEC policy, expose it from a shared formatter, and remove all local implementations.
- Effort: S

#### DUP-003-003 · Relative-time calculation is implemented twice · severity: high · confidence: high
- Locations: `console/ui/src/components/AssistantPanel.tsx:9-15`, `console/ui/src/views/NetworkCompass.tsx:80-86`
- Duplicated behavior: Render elapsed time as “just now,” minutes, hours, or days ago using identical thresholds.
- Divergence: no.
- Evidence:
  ```ts
  // console/ui/src/components/AssistantPanel.tsx:9-15
  function relativeTime(iso: string): string {
    const seconds = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1_000));
    if (seconds < 60) return "just now";
    if (seconds < 3_600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86_400) return `${Math.floor(seconds / 3_600)}h ago`;
    return `${Math.floor(seconds / 86_400)}d ago`;
  }
  ```
  ```ts
  // console/ui/src/views/NetworkCompass.tsx:80-86
  function relativeTime(iso: string): string {
    const seconds = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
    if (seconds < 60) return "just now";
    if (seconds < 3_600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86_400) return `${Math.floor(seconds / 3_600)}h ago`;
    return `${Math.floor(seconds / 86_400)}d ago`;
  }
  ```
- Impact: Threshold, localization, or invalid-date fixes can drift between two user-visible timelines.
- Recommended fix: Move this formatter into `console/ui/src/lib/utils.ts` and consume it from both components.
- Effort: S

#### DUP-003-004 · Security-sensitive HTML escaping is maintained twice · severity: high · confidence: high
- Locations: `console/server/src/notify/oncall.ts:86-88`, `console/server/src/store.ts:562-564`
- Duplicated behavior: Escape ampersands and angle brackets before interpolating untrusted values into Telegram HTML.
- Divergence: no.
- Evidence:
  ```ts
  // console/server/src/notify/oncall.ts:86-88
  function escapeHtml(value: string): string {
    return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  ```
  ```ts
  // console/server/src/store.ts:562-564
  function escapeHtml(value: string): string {
    return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  ```
- Impact: A future escaping correction could protect one notification route but leave the other vulnerable to malformed markup.
- Recommended fix: Put Telegram/HTML escaping in one notification utility and use it from both delivery paths.
- Effort: S

#### DUP-003-005 · Compass time-window wording exists on both sides of the API · severity: high · confidence: high
- Locations: `console/server/src/network/compass.ts:446-450`, `console/ui/src/views/NetworkCompass.tsx:55-59`
- Duplicated behavior: Describe a configured hour window as the last hour, N hours, or rounded N days.
- Divergence: no.
- Evidence:
  ```ts
  // console/server/src/network/compass.ts:446-450
  function windowText(hours: number): string {
    if (hours <= 1) return "the last hour";
    if (hours < 48) return `the last ${hours} hours`;
    return `the last ${Math.round(hours / 24)} days`;
  }
  ```
  ```ts
  // console/ui/src/views/NetworkCompass.tsx:55-59
  function windowLabel(hours: number): string {
    if (hours <= 1) return "the last hour";
    if (hours < 48) return `the last ${hours} hours`;
    return `the last ${Math.round(hours / 24)} days`;
  }
  ```
- Impact: Insight text and screen labels can diverge if the window policy or wording changes.
- Recommended fix: Return a canonical label from the server or share a pure formatter through `@aisoc/shared`.
- Effort: S

### ARCH-001 — Layering violation (1 finding, suppressed: 0)

#### ARCH-001-001 · Central state layer depends on feature policy and notification delivery · severity: critical · confidence: medium
- Locations: `console/server/src/store.ts:34-47`, `console/server/src/store.ts:530-558`
- Evidence:
  ```ts
  // console/server/src/store.ts:34-47
  import { defaultRulePacks, ENGINE_VERSION } from "./detect/feeds.js";
  import { RULE_COUNT } from "./detect/rules.js";
  import { inQuietHours, sendTelegram } from "./notify/telegram.js";
  import { DEFAULT_PLAYBOOKS } from "./response/playbooks.js";
  import { getSettings } from "./settings.js";
  import { listServers } from "./vpn/servers.js";
  ```
  ```ts
  // console/server/src/store.ts:550-558
  if (
    settings.telegram.enabled &&
    settings.notifications.telegramKinds.includes(notification.kind) &&
    !inQuietHours(full.level === "critical" ? 1 : 2)
  ) {
    void sendTelegram(settings.telegram.chatId, `<b>${escapeHtml(full.title)}</b>`);
  }
  ```
- Impact: Persistence/state changes now depend on detection, response, VPN, settings, and outbound delivery concerns, making the store a coupling hub and making lower-level state operations produce hidden external side effects.
- Recommended fix: Keep the store limited to state and persistence; initialize feature defaults in composition code and publish notification events for a notification service to deliver.
- Effort: L

### ARCH-002 — Circular dependency (1 finding, suppressed: 0)

#### ARCH-002-001 · Shared barrel has a type-level self-import cycle · severity: high · confidence: high
- Locations: `console/shared/src/index.ts:1-5`, `console/shared/src/flow.ts:1-2`
- Evidence:
  ```ts
  // console/shared/src/index.ts:1-5
  export * from "./defaults.js";
  export * from "./flow.js";
  export * from "./mitre.js";
  export * from "./net.js";
  export * from "./types.js";
  ```
  ```ts
  // console/shared/src/flow.ts:1-2
  import type { SecurityEvent } from "@aisoc/shared";
  import { inNetwork, sameAddress } from "./net.js";
  ```
- Impact: `index.ts → flow.ts → index.ts` couples an internal module to its public barrel; it is currently type-only but is fragile if the import gains a runtime value.
- Recommended fix: Import `SecurityEvent` directly from `./types.js` inside the shared package.
- Effort: S

### DUP-001 — Exact duplicate block (3 findings, suppressed: 0)

#### DUP-001-001 · ListEditor component is copied between screens · severity: medium · confidence: high
- Locations: `console/ui/src/views/Settings.tsx:292-348`, `console/ui/src/views/RemoteAccess.tsx:401-457`
- Evidence:
  ```tsx
  // console/ui/src/views/Settings.tsx:305-312
  const [draft, setDraft] = useState("");
  return (
    <Field label={label} hint={hint}>
      <div className="flex flex-wrap gap-1">
        {values.map((value) => (
          <Badge key={value} className="gap-1 text-ink">
  ```
  ```tsx
  // console/ui/src/views/RemoteAccess.tsx:414-421
  const [draft, setDraft] = useState("");
  return (
    <Field label={label} hint={hint}>
      <div className="flex flex-wrap gap-1">
        {values.map((value) => (
          <Badge key={value} className="gap-1 text-ink">
  ```
- Impact: Validation, keyboard behavior, accessibility, and duplicate-entry handling must be corrected twice.
- Recommended fix: Extract a typed list editor into the existing UI component layer.
- Effort: S

#### DUP-001-002 · Fact display component is copied locally · severity: info · confidence: high · label: probably-intentional
- Locations: `console/ui/src/views/Vpn.tsx:196-206`, `console/ui/src/views/RemoteAccess.tsx:278-288`
- Evidence:
  ```tsx
  // console/ui/src/views/Vpn.tsx:196-203
  function Fact({ label, value, sub }: { label: string; value: string; sub?: string }) {
    return (
      <div className="rounded-sm border border-edge bg-shell px-2 py-1.5">
        <div className="text-[10px] uppercase tracking-wide text-ink-dim">{label}</div>
        <div className="truncate font-mono text-[13px] text-ink" title={value}>
  ```
  ```tsx
  // console/ui/src/views/RemoteAccess.tsx:278-285
  function Fact({ label, value, sub }: { label: string; value: string; sub?: string }) {
    return (
      <div className="rounded-sm border border-edge bg-shell px-2 py-1.5">
        <div className="text-[10px] uppercase tracking-wide text-ink-dim">{label}</div>
        <div className="truncate font-mono text-[13px] text-ink" title={value}>
  ```
- Impact: Minor presentation changes can drift, although keeping this small feature-local component self-contained may be intentional.
- Recommended fix: Leave local if feature isolation is preferred; otherwise promote it to a small shared display primitive.
- Effort: S

#### DUP-001-003 · Feature-local alert/action row fragments repeat · severity: info · confidence: high · label: probably-intentional
- Locations: `console/ui/src/views/Incidents.tsx:258-277`, `console/ui/src/views/Assets.tsx:200-222`, `console/ui/src/views/Response.tsx:128-137`, `console/ui/src/components/DetailPanel.tsx:222-231`
- Evidence:
  ```tsx
  // console/ui/src/views/Incidents.tsx:258-265
  <button
    key={alert.id}
    type="button"
    onClick={() => {
      selectAlert(alert.id);
      setView("triage");
    }}
  ```
  ```tsx
  // console/ui/src/views/Assets.tsx:200-207
  <button
    key={alert.id}
    type="button"
    onClick={() => {
      selectAlert(alert.id);
      setView("triage");
    }}
  ```
- Impact: The fragments share navigation and status behavior, but their trailing content differs by feature and the duplication appears intentionally local.
- Recommended fix: Retain feature-local rendering unless behavior starts changing; then extract only the shared navigation/status shell.
- Effort: S

### DUP-002 — Near-duplicate block (1 finding, suppressed: 0)

#### DUP-002-001 · VPN and remote-access readiness panels share the same implementation · severity: medium · confidence: high
- Locations: `console/ui/src/views/Vpn.tsx:324-398`, `console/ui/src/views/RemoteAccess.tsx:295-362`
- Evidence:
  ```tsx
  // console/ui/src/views/Vpn.tsx:335-342
  const refresh = useCallback(() => {
    setLoading(true);
    api
      .vpnPreflight()
      .then(setChecks)
      .catch(() => setChecks([]))
      .finally(() => setLoading(false));
  ```
  ```tsx
  // console/ui/src/views/RemoteAccess.tsx:299-306
  const refresh = useCallback(() => {
    setLoading(true);
    api
      .remoteAccessPreflight()
      .then(setChecks)
      .catch(() => setChecks([]))
      .finally(() => setLoading(false));
  ```
- Impact: Loading, error, retry, check rendering, and success-state behavior are duplicated across roughly 70-line components.
- Recommended fix: Extract a readiness-check component or hook parameterized by the loader, refresh signature, and success text.
- Effort: M

### DUP-004 — Duplicate type/schema (2 findings, suppressed: 0)

#### DUP-004-001 · UI state repeats the server Snapshot payload schema · severity: medium · confidence: high
- Locations: `console/shared/src/types.ts:1309-1334`, `console/ui/src/store.ts:88-113`
- Evidence:
  ```ts
  // console/shared/src/types.ts:1309-1316
  export interface Snapshot {
    events: SecurityEvent[];
    networkFlows: NetworkFlow[];
    compass: CompassSummary;
    compassReview: CompassReview | null;
    alerts: Alert[];
    llmCalls: LlmCall[];
  ```
  ```ts
  // console/ui/src/store.ts:88-95
  type State = {
    connected: boolean;
    events: SecurityEvent[];
    networkFlows: NetworkFlow[];
    compass: CompassSummary | null;
    compassReview: CompassReview | null;
    alerts: Alert[];
  ```
- Impact: Adding or changing snapshot fields requires a manual parallel edit in the UI state, with additional nullable differences obscuring which fields are transport state versus local state.
- Recommended fix: Define the remote portion from `Snapshot` using an explicit mapped/derived type and intersect it with UI-only state and actions.
- Effort: M

#### DUP-004-002 · ExportKind union is independently defined in server and UI packages · severity: medium · confidence: high
- Locations: `console/server/src/reports.ts:207-209`, `console/ui/src/lib/api.ts:111-115`
- Evidence:
  ```ts
  // console/server/src/reports.ts:207-209
  export type ExportKind =
    "alerts" | "incidents" | "actions" | "audit" | "quarantine" | "assets";
  ```
  ```ts
  // console/ui/src/lib/api.ts:111-115
  export type ExportKind =
    "alerts" | "incidents" | "actions" | "audit" | "quarantine" | "assets";
  ```
- Impact: A new backend export can compile while remaining unavailable or incorrectly typed in the UI.
- Recommended fix: Move `ExportKind` into `@aisoc/shared` and import it from both packages.
- Effort: S

### DUP-005 — Duplicate config/constants (3 findings, suppressed: 0)

#### DUP-005-001 · Remote-access empty state has two sources of truth · severity: low · confidence: high
- Locations: `console/server/src/store.ts:107-119`, `console/server/src/remoteaccess/manager.ts:25-39`
- Evidence:
  ```ts
  // console/server/src/store.ts:107-114
  let remoteAccess: RemoteAccessState = {
    present: false,
    online: false,
    backendState: null,
    node: "",
    dnsName: "",
    tailnetIP: null,
  ```
  ```ts
  // console/server/src/remoteaccess/manager.ts:25-32
  function blank(): RemoteAccessState {
    return {
      present: false,
      online: false,
      backendState: null,
      node: "",
      dnsName: "",
  ```
- Impact: Adding a state field or changing its default can produce different reset and startup states.
- Recommended fix: Export one `blankRemoteAccessState` factory from the manager or a domain-defaults module.
- Effort: S

#### DUP-005-002 · Agent control-socket contract is repeated across processes · severity: low · confidence: high
- Locations: `agent/aisoc.py:64-66`, `console/server/src/response/agent.ts:17-22`, `console/server/src/vpn/manager.ts:40-42`
- Evidence:
  ```py
  # agent/aisoc.py:64-66
  CONTROL_SOCKET = os.environ.get("AISOC_CONTROL_SOCKET",
      "/run/aisoc/control.sock" if os.path.isdir("/run/aisoc")
      else os.path.join(BASE, "suricata/logs/control.sock"))
  ```
  ```ts
  // console/server/src/response/agent.ts:17-22
  const SOCKET = process.env.AISOC_CONTROL_SOCKET ?? "/run/aisoc/control.sock";
  const TIMEOUT_MS = 105_000;
  const MAX_REPLY = 8_192;
  ```
  ```ts
  // console/server/src/vpn/manager.ts:40-42
  const CONFIG_DIR = join(DATA_DIR, "wg");
  const CONTROL_SOCKET = process.env.AISOC_CONTROL_SOCKET ?? "/run/aisoc/control.sock";
  ```
- Impact: Deployment overrides and fallback behavior can drift between the socket owner and its clients.
- Recommended fix: Treat the socket value as deployment-injected configuration and expose one server-side path constant for TypeScript clients.
- Effort: S

#### DUP-005-003 · Shared severity labels are redefined instead of consumed · severity: low · confidence: high
- Locations: `console/shared/src/defaults.ts:192-197`, `console/ui/src/lib/utils.ts:20-22`
- Evidence:
  ```ts
  // console/shared/src/defaults.ts:192-197
  export const SEVERITY_LABEL: Record<number, string> = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
  };
  ```
  ```ts
  // console/ui/src/lib/utils.ts:20-22
  export function severityLabel(severity: number): string {
    return { 1: "critical", 2: "high", 3: "medium", 4: "low" }[severity] ?? "unknown";
  }
  ```
- Impact: The exported shared constant is unused while the UI maintains a separate mapping.
- Recommended fix: Make the UI helper read `SEVERITY_LABEL`, including its explicit unknown fallback.
- Effort: S

### DUP-006 — Duplicate test/helper boilerplate (1 finding, suppressed: 0)

#### DUP-006-001 · Assistant tests repeat temporary settings bootstrap · severity: low · confidence: high
- Locations: `console/server/src/assistant/chat.test.ts:8-32`, `console/server/src/assistant/chat.persist.test.ts:15-30`, `console/server/src/assistant/models.test.ts:10-34`
- Evidence:
  ```ts
  // console/server/src/assistant/chat.test.ts:8-15
  const dataDir = mkdtempSync(join(tmpdir(), "aisoc-assistant-chat-test-"));
  writeFileSync(
    join(dataDir, "settings.json"),
    JSON.stringify({
      firstTriage: {
        provider: "openai-compatible",
        endpoint: "http://127.0.0.1:9/v1/chat/completions",
  ```
  ```ts
  // console/server/src/assistant/models.test.ts:10-17
  const dataDir = mkdtempSync(join(tmpdir(), "aisoc-analyst-models-test-"));
  writeFileSync(
    join(dataDir, "settings.json"),
    JSON.stringify({
      firstTriage: {
        provider: "openai-compatible",
        endpoint: "http://127.0.0.1:9/v1/chat/completions",
  ```
- Impact: Test defaults can drift and obscure which fields are relevant to each test.
- Recommended fix: Add a test-only temporary data/settings factory with per-test overrides.
- Effort: S

### ARCH-003 — God file (4 findings, suppressed: 0)

#### ARCH-003-001 · Server entrypoint combines composition with 41 route handlers · severity: medium · confidence: high
- Locations: `console/server/src/index.ts:1-1328`
- Evidence:
  ```ts
  // console/server/src/index.ts:24-31
  import { listAnalystModels } from "./assistant/models.js";
  import { installTrustBoundary, issueSession } from "./auth.js";
  import { startConsoleControlServer } from "./control.js";
  import { defaultRulePacks } from "./detect/feeds.js";
  import { RULE_COUNT, RULES } from "./detect/rules.js";
  ```
- Impact: With 1328 lines, 45 import declarations, and 41 route registrations, unrelated feature changes converge on one composition file.
- Recommended fix: Split route registration into feature routers while retaining listener startup and dependency composition in the entrypoint.
- Effort: L

#### ARCH-003-002 · Host agent combines enforcement, persistence, IPC, enrichment, LLM, and ingest · severity: medium · confidence: high
- Locations: `agent/aisoc.py:1-1455`
- Evidence:
  ```py
  # agent/aisoc.py:1029-1037
  class Agent:
      def __init__(self):
          self.guard = Guard()
          self.seen = {}
          self.offenders = OffenderStore()
          self.control_ledger = ControlLedger()
          self.history = {}
          self.control = ControlServer()
  ```
- Impact: The 1455-line process has 33 top-level functions and five classes spanning security-critical concerns with different change drivers.
- Recommended fix: Separate control protocol, firewall enforcement, enrichment/LLM, persistence, and event ingestion behind narrow internal interfaces.
- Effort: L

#### ARCH-003-003 · Settings view renders sixteen configuration domains in one component file · severity: medium · confidence: high
- Locations: `console/ui/src/views/Settings.tsx:1-1628`
- Evidence:
  ```tsx
  // console/ui/src/views/Settings.tsx:350-369
  export function SettingsView() {
    const settings = useStore((s) => s.settings);
    const secrets = useStore((s) => s.secrets);
    const analyst = useStore((s) => s.analyst);
    const [draft, setDraft] = useState<Settings>(settings);
    const patch = <K extends keyof Settings>(key: K, value: Partial<Settings[K]>) =>
      setDraft((prev) => ({ ...prev, [key]: { ...prev[key], ...value } }));
  ```
- Impact: The 1628-line view couples provider, triage, notifications, VPN, remote-access, detection, guardrail, and site-setting forms.
- Recommended fix: Split each settings domain into a focused section component while keeping draft/save coordination at the view level.
- Effort: L

#### ARCH-003-004 · Store owns state, metrics, messaging, delivery, migration, and persistence · severity: medium · confidence: high
- Locations: `console/server/src/store.ts:1-857`
- Evidence:
  ```ts
  // console/server/src/store.ts:772-781
  function persistSoon(): void {
    if (persistTimer) return;
    persistTimer = setTimeout(() => {
      persistTimer = null;
      writePrivateAtomic(
        STATE_FILE,
        JSON.stringify({
  ```
- Impact: The 857-line module exports 60 functions and mixes six distinct responsibilities, making it both a change hotspot and an architectural dependency sink.
- Recommended fix: Separate repositories/persistence, metrics, subscriptions, notifications, and feature-specific state services.
- Effort: L

### ARCH-004 — Coupling hotspot (1 finding, suppressed: 0)

#### ARCH-004-001 · Composition, barrel, UI store, and utility modules dominate coupling · severity: medium · confidence: high
- Locations: `console/server/src/index.ts:1-108`, `console/shared/src/index.ts:1-5`, `console/ui/src/App.tsx:3-28`, `console/ui/src/store.ts:1-31`, `console/ui/src/lib/utils.ts:1-4`
- Evidence:
  ```ts
  // console/ui/src/App.tsx:3-10
  import { ActivityBar } from "@/components/ActivityBar";
  import { AssistantPanel } from "@/components/AssistantPanel";
  import { DetailPanel } from "@/components/DetailPanel";
  import { NotificationCenter } from "@/components/NotificationCenter";
  import { ServiceTerminal } from "@/components/ServiceTerminal";
  import { StatusBar } from "@/components/StatusBar";
  import { Toasts } from "@/components/Toasts";
  ```
  ```ts
  // console/shared/src/index.ts:1-5
  export * from "./defaults.js";
  export * from "./flow.js";
  export * from "./mitre.js";
  export * from "./net.js";
  export * from "./types.js";
  ```
- Impact: `@aisoc/shared` has 74 in-scope consumers, server `index.ts` has 45 imports, UI `App.tsx` has 28 imports, UI utilities have 29 importers, and the UI store has 23 importers.
- Recommended fix: Preserve the barrel as a deliberate contract, but split composition/routes and expose narrower store selectors and focused utility modules.
- Effort: M

### ARCH-005 — Dead code (1 finding, suppressed: 0)

#### ARCH-005-001 · Exported totalBytes helper is never consumed · severity: low · confidence: high
- Locations: `console/shared/src/flow.ts:134-136`
- Evidence:
  ```ts
  // console/shared/src/flow.ts:134-136
  export function totalBytes(event: SecurityEvent): number {
    return event.bytesToServer + event.bytesToClient;
  }
  ```
- Impact: The helper enlarges the public contract without providing value and may mislead callers about the preferred directional byte semantics.
- Recommended fix: Remove the export and function if no planned consumer exists.
- Effort: S

### ARCH-008 — API surface bloat (1 finding, suppressed: 0)

#### ARCH-008-001 · ipv6Number is public but only used inside its defining module · severity: low · confidence: high
- Locations: `console/shared/src/net.ts:15-35`
- Evidence:
  ```ts
  // console/shared/src/net.ts:15-21
  export function ipv6Number(input: string): bigint | null {
    let ip = input.toLowerCase().split("%", 1)[0]!;
    if (!ip.includes(":")) return null;
    if (ip.includes(".")) {
      const lastColon = ip.lastIndexOf(":");
      const v4 = ipv4Number(ip.slice(lastColon + 1));
  ```
- Impact: An implementation detail is exposed through the package barrel and becomes harder to change.
- Recommended fix: Make `ipv6Number` module-private unless external numeric IPv6 conversion is an intentional supported API.
- Effort: S

### QUAL-001 — Error/typing debt (1 finding, suppressed: 0)

#### QUAL-001-001 · Notification read failure is silently swallowed · severity: low · confidence: high
- Locations: `console/ui/src/components/NotificationCenter.tsx:94-100`
- Evidence:
  ```tsx
  // console/ui/src/components/NotificationCenter.tsx:94-100
  <button
    key={notification.id}
    type="button"
    onClick={() => {
      void api.markNotificationsRead([notification.id]).catch(() => {});
      follow(notification.linkView, notification.linkId);
    }}
  ```
- Impact: The UI navigates as though the notification was marked read, while network or authorization failures remain invisible and the unread state can reappear.
- Recommended fix: Handle the rejection through the existing toast/error path or explicitly implement and document an optimistic rollback policy.
- Effort: S

## 3. Architecture report
- Module map:
  ```mermaid
  graph TD
    Deploy[deployment/config] --> Agent[agent and privileged helpers]
    Deploy --> Server[console/server composition]
    Desktop[console/desktop] --> UI[console/ui]
    UI --> Shared[console/shared]
    UI --> API[server HTTP and WebSocket API]
    Server --> Shared
    Server --> Features[detect, triage, incidents, response, VPN, network]
    Features --> Store[state and persistence]
    Features --> Infra[settings, crypto, paths, notifications]
    Server --> Agent
  ```
- Import cycles:
  - Type-level cycle: `console/shared/src/index.ts:2 → console/shared/src/flow.ts:1 → console/shared/src/index.ts:2` (ARCH-002-001).
  - No relative-import module cycles were found in `console/server` or `console/ui`.
- Layering violations:
  - `console/server/src/store.ts:34-47` imports detection, notification, response, VPN, and settings feature modules from the lower-level state layer.
  - `console/server/src/store.ts:530-558` directly performs Telegram delivery during a state mutation (ARCH-001-001).
- Hotspots:
  - `console/shared/src/index.ts:1-5`: package-barrel fan-in 74.
  - `console/server/src/index.ts:1-108`: fan-out 45; 1328 LOC.
  - `console/ui/src/lib/utils.ts:1-130`: fan-in 29.
  - `console/ui/src/App.tsx:3-28`: fan-out 28.
  - `console/ui/src/store.ts:1-31`: fan-in 23.
  - Size outliers: `console/ui/src/views/Settings.tsx` 1628 LOC; `agent/aisoc.py` 1455; `console/shared/src/types.ts` 1406; `console/server/src/index.ts` 1328; `console/ui/src/views/NetworkCompass.tsx` 926.
- Dead code:
  - `console/shared/src/flow.ts:134-136` — `totalBytes` has no consumer (ARCH-005-001).
  - `console/shared/src/defaults.ts:192-197` — `SEVERITY_LABEL` has no consumer because the UI repeats the mapping (DUP-005-003).

## 4. Needs human review
None. No low-confidence findings were retained.

## 5. Prioritized remediation plan
1. Fix DUP-003-001 by centralizing the framed Python IPC protocol and exact-read behavior.
2. Fix ARCH-001-001 and ARCH-003-004 by separating state/persistence from feature defaults and notification delivery.
3. Fix DUP-003-002, DUP-003-003, DUP-003-004, and DUP-003-005 by establishing canonical shared formatting and escaping utilities.
4. Fix ARCH-002-001 by replacing the shared package self-import with a direct type-module import.
5. Fix ARCH-003-001 by moving route registration into feature-focused server modules.
6. Fix ARCH-003-002 by separating the host agent’s enforcement, IPC, enrichment, persistence, and ingestion responsibilities.
7. Fix ARCH-003-003, DUP-001-001, and DUP-002-001 by splitting settings domains and extracting reusable list/readiness UI components.
8. Fix DUP-004-001 and DUP-004-002 by deriving client transport state from `Snapshot` and moving `ExportKind` into `@aisoc/shared`.
9. Fix DUP-005-001, DUP-005-002, and DUP-005-003 by consolidating state factories and cross-process constants.
10. Fix DUP-006-001, ARCH-005-001, ARCH-008-001, and QUAL-001-001 through shared test setup, API pruning, and explicit rejection handling.
11. Reassess DUP-001-002 and DUP-001-003 only if their currently feature-local presentation behavior begins to drift.

## 6. Scanner self-check
- [x] All findings have file:line evidence
- [x] Excluded globs respected
- [x] Per-rule cap applied (suppressed counts reported)
- [x] No file modified other than this report
