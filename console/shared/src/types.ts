/** Suricata convention: 1 is the most severe. */
export type Severity = 1 | 2 | 3 | 4;

export type Protocol = "TCP" | "UDP" | "ICMP";

/**
 * Where an event came from. `eve` and `seed` are the network sensors; `host` is
 * the auditd bridge; `tetragon` and `k3s-audit` are the cluster's syscall and
 * API-server streams, which arrive as files on this host and are therefore
 * readable without depending on the cluster being healthy.
 */
export type EventSource = "seed" | "eve" | "host" | "tetragon" | "k3s-audit";

/** The sources an operator can select as the primary ingest mode. */
export type IngestSource = Extract<EventSource, "seed" | "eve" | "host">;

export interface SecurityEvent {
  id: string;
  ts: string;
  srcIp: string;
  srcPort: number;
  destIp: string;
  destPort: number;
  proto: Protocol;
  appProto?: string;
  signature: string;
  signatureId: number;
  category: string;
  severity: Severity;
  tags: string[];
  direction: "to_server" | "to_client";
  sni?: string;
  hostname?: string;
  url?: string;
  userAgent?: string;
  /**
   * Byte counters as Suricata reports them, kept apart rather than summed.
   * `direction` above is the direction of the packet that matched the
   * signature, so it says nothing about which way the payload went — a GET that
   * pulls down 700 MB is still a `to_server` alert. Anything reasoning about
   * volume must pick a side; `outboundBytes` in detect/flow.ts does that
   * relative to whichever address is ours.
   */
  bytesToServer: number;
  bytesToClient: number;
  /**
   * Packet counts for the same two directions, where the sensor reports them.
   * Bytes alone cannot tell a transfer from the ACK stream acknowledging one:
   * 813 kB across 13,468 packets is 60 B each, which is a bare TCP header.
   */
  pktsToServer?: number;
  pktsToClient?: number;
  /**
   * The end that opened the flow, which is what every `*ToServer`/`*ToClient`
   * counter above is anchored to. Absent on sensors that don't report it, where
   * it has to be inferred from `direction`.
   */
  flowInitiatorIp?: string;
  source: EventSource;
  /** Set once the event is admitted to the triage queue. */
  alertId?: string;

  /** Endpoint telemetry. Present on host-sourced events, absent on pure network alerts. */
  assetId?: string;
  processName?: string;
  processPid?: number;
  processPath?: string;
  parentProcess?: string;
  user?: string;
  filePath?: string;
  fileSha256?: string;
  /** Set by the correlator when several events belong to one scripted behaviour. */
  scenario?: string;

  /**
   * Cluster context. Present on `tetragon` and `k3s-audit` events, absent on
   * everything else: a `pods/exec` by a ServiceAccount has no source port and
   * no signature id, and squeezing it into the network fields would lose the
   * only three facts that matter — who, which verb, which object.
   */
  k8s?: KubernetesContext;
}

export interface KubernetesContext {
  /** API verb (`create`, `delete`, `get`) for audit events. */
  verb?: string;
  /** `secrets`, `pods/exec`, `clusterrolebindings`. */
  resource?: string;
  /** Namespace of the object acted on, not of the caller. */
  namespace?: string;
  objectName?: string;
  /** Raw authenticated identity, e.g. `system:serviceaccount:prod:builder`. */
  subject?: string;
  subjectKind?: "user" | "serviceaccount" | "node" | "anonymous";
  /** Namespace the ServiceAccount itself belongs to, when the subject is one. */
  subjectNamespace?: string;
  /** `allow` or `forbid`, as the authorizer decided. */
  decision?: "allow" | "forbid";
  responseCode?: number;
  /** Tetragon only: the workload and container the process ran in. */
  workload?: string;
  container?: string;
  /** Tetragon only: the kernel function a kprobe policy hooked. */
  kprobe?: string;
}

// ---------------------------------------------------------------------------
// Network Compass — privacy-preserving flow visibility
// ---------------------------------------------------------------------------

export type FlowDirection = "outbound" | "inbound" | "internal" | "unknown";
export type DomainSource = "dns" | "tls" | "http";

/**
 * How the destination name was obtained. Nothing here is proof: `asserted`
 * means the client named the host on this very connection (TLS SNI or an HTTP
 * Host header, both unauthenticated), and `inferred` means a recent DNS answer
 * on the same sensor mapped the address to a name. A shared CDN address can
 * therefore carry a neighbour's name.
 */
export type DomainConfidence = "asserted" | "inferred" | "unknown";

/**
 * Whether a person plausibly caused the connection. `infrastructure` is machine
 * chatter — name lookups, clock sync, service discovery — which dominates any
 * raw capture and is hidden from the default view.
 */
export type TrafficClass = "web" | "infrastructure" | "local" | "other";

/**
 * A connection summary, deliberately separate from SecurityEvent. Raw flow
 * records never enter triage; a derived aggregate may cross the documented
 * Compass beacon bridge.
 */
export interface NetworkFlow {
  id: string;
  flowId: string;
  sensor: string;
  startedAt: string;
  endedAt: string;
  updatedAt: string;
  localIp: string;
  localPort: number;
  remoteIp: string;
  remotePort: number;
  direction: FlowDirection;
  trafficClass: TrafficClass;
  proto: string;
  appProto: string | null;
  /** Full observed host, e.g. `detectportal.firefox.com`. */
  hostname: string | null;
  /** Registrable form of `hostname`, e.g. `firefox.com`. Groups the UI. */
  domain: string | null;
  domainSource: DomainSource | null;
  domainConfidence: DomainConfidence;
  country: string | null;
  /** Origin network from the bundled routing snapshot, e.g. `AS15169 GOOGLE`. */
  asn: string | null;
  organization: string | null;
  bytesUp: number;
  bytesDown: number;
  packetsUp: number;
  packetsDown: number;
  state: string | null;
  /** Coarse, non-sensitive local classification. Null means unclassified. */
  category: string | null;
  /** Kernel `comm` for the exact socket owner. Null means no exact match. */
  processName: string | null;
}

export interface CompassProcess {
  /** Null is rendered as unknown; it is never filled by inference. */
  name: string | null;
  flows: number;
  bytesUp: number;
  bytesDown: number;
}

/** One site or address, with every connection to it in the window folded in. */
export interface CompassDestination {
  key: string;
  label: string;
  hostnames: string[];
  category: string | null;
  categoryLabel: string | null;
  country: string | null;
  asn: string | null;
  organization: string | null;
  trafficClass: TrafficClass;
  confidence: DomainConfidence;
  flows: number;
  /** Connections carried in the clear, where anyone on the path can read them. */
  plaintextFlows: number;
  bytesUp: number;
  bytesDown: number;
  firstSeen: string;
  lastSeen: string;
  /** Distinct days in the long-term daily totals. 1 means "first seen today". */
  knownDays: number;
  firstSeenDay: string | null;
  processes: CompassProcess[];
}

export interface CompassCategory {
  id: string;
  label: string;
  flows: number;
  activeDays: number;
  bytesUp: number;
  bytesDown: number;
}

export type InsightKind =
  | "new-destination"
  | "top-talker"
  | "unencrypted"
  | "background-chatter"
  | "unusual-upload";

/**
 * A plain-language statement of fact about the retained window. Insights are
 * computed locally by deterministic rules; no model sees a flow, and nothing
 * here infers anything about the person beyond what they can read themselves.
 */
export interface CompassInsight {
  id: string;
  kind: InsightKind;
  title: string;
  detail: string;
  /** Set when the insight can be acted on by muting a site. */
  domain: string | null;
  tone: "neutral" | "watch";
}

export type InsightStatus = "dismissed" | "snoozed";

export type ReviewAssessment = "expected" | "worth_checking" | "unexpected";

export interface CompassReviewFinding {
  /** Echoed from the input. A site the model invented is dropped, not shown. */
  site: string;
  assessment: ReviewAssessment;
  reason: string;
}

/**
 * A first-tier model's read of the aggregate destination table. The model sees
 * registrable domains and coarse counters only — never a raw flow, hostname,
 * local address, port, or timestamp.
 */
/** What the model returns for a Compass review, before reconciliation. */
export interface CompassReviewOutput {
  summary: string;
  findings: CompassReviewFinding[];
}

export interface CompassReview {
  id: string;
  createdAt: string;
  windowHours: number;
  model: string;
  summary: string;
  findings: CompassReviewFinding[];
  /** Sites the model named that were not in the input, kept for honesty. */
  invented: string[];
  sitesReviewed: number;
  error: string | null;
}

/**
 * A follow-up turn in an analyst conversation. The operator's question and the
 * model's plain-text answer; `model` records which model produced the turn so
 * a conversation can mix models and still show where each answer came from.
 */
export interface AnalystChatMessage {
  id: string;
  role: "user" | "assistant";
  text: string;
  model: string;
  createdAt: string;
  /** Set when the model call failed; `text` then carries the error message. */
  error: string | null;
}

/** One entry in an analyst-chat model picker. */
export interface AnalystChatModelOption {
  /** What the client sends back as `model`. */
  id: string;
  /** Human label for the picker. */
  label: string;
  /** The model name actually sent to the endpoint. */
  model: string;
  provider: LlmProvider;
  /** "stage" is a configured triage stage; "live" came from the endpoint's model list. */
  source: "stage" | "live";
}

export type AssistanceSubjectKind = "alert" | "incident" | "dns" | "compass";

/** A persisted follow-up conversation tied to one immutable investigation snapshot. */
export interface AssistanceChat {
  id: string;
  subjectKind: AssistanceSubjectKind;
  subjectId: string;
  createdAt: string;
  updatedAt: string;
  model: string;
  messages: AnalystChatMessage[];
}

export interface CompassSummary {
  enabled: boolean;
  paused: boolean;
  insightsEnabled: boolean;
  /** Size of the window every figure below is computed over. */
  windowHours: number;
  retainedFlows: number;
  earliestFlowAt: string | null;
  bytesUp: number;
  bytesDown: number;
  directionCounts: Record<FlowDirection, number>;
  destinations: CompassDestination[];
  categories: CompassCategory[];
  insights: CompassInsight[];
  namedFlows: number;
  unnamedFlows: number;
  backgroundFlows: number;
  backgroundBytes: number;
  attributedFlows: number;
  unattributedFlows: number;
  /** Exact socket-owner matches divided by every retained flow. */
  attributionCoverage: number;
}

export type DnsQueryStatus = "blocked" | "forwarded" | "cached" | "other";

export interface DnsQuery {
  id: number;
  at: string;
  client: string;
  domain: string;
  /** Record type as written by dig, e.g. `A`, `HTTPS`. */
  type: string;
  status: DnsQueryStatus;
  upstream: string | null;
}

export interface DnsCount {
  key: string;
  queries: number;
  blocked: number;
}

export interface DnsSummary {
  /**
   * False when the resolver is not running or its database cannot be read.
   * `error` carries the reason so the view can say which, rather than render an
   * empty panel that looks like a quiet network.
   */
  available: boolean;
  error: string | null;
  windowHours: number;
  /**
   * FTL's global blocking switch (what `pihole -d` / `pihole -e` flip). Null
   * when the resolver is unreachable, so the view hides the toggle instead of
   * guessing at a state it cannot act on.
   */
  blockingEnabled: boolean | null;
  totals: {
    queries: number;
    blocked: number;
    cached: number;
    forwarded: number;
    clients: number;
  };
  recent: DnsQuery[];
  /** Permitted domains only — FTL keeps blocked ones in a disjoint list. */
  topDomains: DnsCount[];
  blockedDomains: DnsCount[];
  topClients: DnsCount[];
}

export interface NetworkCompassConfig {
  /** Collection is explicit opt-in. Security alert ingest is unaffected. */
  enabled: boolean;
  paused: boolean;
  insightsEnabled: boolean;
  /**
   * Sends the aggregate destination table to the first-tier model on explicit
   * request. Off by default: everything else in Compass is computed locally,
   * and this is the one control that lets any of it leave the machine.
   */
  aiReviewEnabled: boolean;
  /** Locally score retained flows for the narrow beacon-alert bridge. */
  beaconDetectionEnabled: boolean;
  /** Destination keys retained normally but barred from beacon alerting. */
  beaconSuppressions: string[];
  rawRetentionHours: number;
  /**
   * How long per-destination daily totals outlive the raw flows they came from.
   * This is what makes "you have never contacted this destination before"
   * answerable. Zero keeps no history at all.
   */
  historyDays: number;
  excludedDomains: string[];
}

export type TriageStage = "pending" | "first_triage" | "second_triage" | "resolved" | "needs_human";

export type Verdict = "BLOCK" | "WATCH" | "IGNORE";

export type NoteKind = "override" | "comment" | "system";

export interface Note {
  id: string;
  at: string;
  author: string;
  kind: NoteKind;
  body: string;
}

export interface HumanOverride {
  verdict: Verdict;
  by: string;
  at: string;
  note: string;
  /** What the pipeline had decided before a human changed it. */
  previousVerdict: Verdict | null;
}

export interface Alert {
  id: string;
  /** Compass-derived alerts are permanently ineligible for automatic response. */
  origin: "event" | "compass_beacon";
  event: SecurityEvent;
  stage: TriageStage;
  verdict: Verdict | null;
  confidence: number;
  /** Model that produced the current verdict. */
  model: string | null;
  reason: string | null;
  createdAt: string;
  updatedAt: string;
  resolvedAt: string | null;
  /** Why first triage handed off, e.g. "confidence 0.41 < 0.70". */
  escalationReason: string | null;
  humanOverride: HumanOverride | null;
  notes: Note[];
  llmCallIds: string[];
  /** Security incident this alert was correlated into. */
  incidentId: string | null;
  /** On-call page raised for this alert, if any. */
  pageId: string | null;

  /** What the deterministic engine found before any model was consulted. */
  detection: Detection | null;
  /** Threat-intel reputation for the remote indicator. */
  enrichment: Enrichment | null;
  assetId: string | null;
  /** Response actions proposed or applied for this alert. */
  responseIds: string[];
}

export type LlmProvider = "openai-compatible" | "anthropic" | "codex-proxy";

export type LlmStatus = "running" | "ok" | "error" | "timeout";

export type LlmStageName =
  | "first_triage"
  | "second_triage"
  | "connection_test"
  | "incident_narrative"
  | "compass_review"
  | "compass_chat"
  | "assistant_chat";

/** An analyst chat turn is plain text, not a structured verdict. */
export interface AnalystChatOutput {
  reply: string;
}

export type CompassChatOutput = AnalystChatOutput;

export interface TokenUsage {
  prompt: number;
  completion: number;
  total: number;
}

export interface LlmCall {
  id: string;
  alertId: string | null;
  eventId: string | null;
  /** Set when one call covered several alerts; `alertId` is null in that case. */
  batchAlertIds: string[] | null;
  stage: LlmStageName;
  provider: LlmProvider;
  model: string;
  endpoint: string;
  startedAt: string;
  finishedAt: string | null;
  latencyMs: number | null;
  status: LlmStatus;
  temperature: number;
  maxTokens: number;
  systemPrompt: string;
  userPrompt: string;
  rawResponse: string | null;
  reasoning: string | null;
  /** The structured output for this stage; shape depends on `stage`. */
  parsed: TriageVerdict | CompassReviewOutput | AnalystChatOutput | null;
  /**
   * True when the JSON shape was constrained at the sampler rather than merely
   * asked for in the prompt — a trust signal the codex proxy reports back.
   */
  schemaEnforced: boolean | null;
  /** Human-readable statement of what the pipeline did with this result. */
  decisionApplied: string | null;
  tokens: TokenUsage | null;
  error: string | null;
}

export interface TriageVerdict {
  verdict: Verdict;
  confidence: number;
  reason: string;
  category?: string;
}

export type NotifyChannel = "telegram" | "email";

export interface NotifyAttempt {
  at: string;
  personId: string;
  personName: string;
  channel: NotifyChannel;
  ok: boolean;
  error: string | null;
}

export interface OncallIncident {
  id: string;
  alertId: string;
  createdAt: string;
  /** Index into the rotation order built when the incident opened. */
  rotation: string[];
  currentIndex: number;
  attempts: NotifyAttempt[];
  acked: boolean;
  ackedBy: string | null;
  ackedAt: string | null;
  /** Rotation ran out with nobody acking. */
  exhausted: boolean;
  nextEscalationAt: string | null;
  closedAt: string | null;
}

export interface Person {
  id: string;
  name: string;
  telegramId: string;
  email: string;
  active: boolean;
}

/** Weekly recurring shift. Hours are local, `endHour` may wrap past midnight. */
export interface ShiftEntry {
  id: string;
  personId: string;
  /** 0 = Sunday. */
  days: number[];
  startHour: number;
  endHour: number;
}

export interface StageConfig {
  provider: LlmProvider;
  endpoint: string;
  model: string;
  temperature: number;
  maxTokens: number;
  timeoutMs: number;
  /** Reference into the encrypted secret store; empty means no key needed. */
  apiKeySecret: string;
}

export interface FirstTriageConfig extends StageConfig {
  /** At or above this confidence, an IGNORE/WATCH closes without escalating. */
  autoCloseConfidence: number;
  /** Below this confidence, always escalate. */
  escalateBelowConfidence: number;
  /** Suricata categories that always escalate regardless of confidence. */
  escalateCategories: string[];
  /** Severity at or below this number escalates (1 is worst). */
  escalateAtOrBelowSeverity: number;
  /** These verdicts always escalate. */
  escalateVerdicts: Verdict[];
}

export interface SecondTriageConfig extends StageConfig {
  /** false = every second-triage verdict lands in needs_human. */
  autoResolve: boolean;
  /** With autoResolve on, verdicts under this confidence still need a human. */
  autoResolveConfidence: number;
  /** Alerts per model call. 1 disables batching and restores per-alert isolation. */
  batchSize: number;
  /** How long a partial batch waits for company before it is sent anyway. */
  batchLingerMs: number;
}

export interface IngestConfig {
  source: IngestSource;
  evePath: string;
  eventsPerSecond: number;
  /** Only severities at or below this enter triage (1 is worst). */
  maxTriageSeverity: number;
  paused: boolean;
}

/**
 * Cluster telemetry, read from the root collector's spool. Independent of
 * `ingest.source`: the network sensor and the cluster streams are different
 * vantage points, not alternatives, and losing one must not silence the other.
 */
export interface ClusterTelemetryConfig {
  enabled: boolean;
  /** Spool written by scripts/cluster_tail.py, not the root-only source files. */
  spoolPath: string;
  /**
   * How long the spool may be silent before coverage is reported as degraded.
   * Longer than the network sensors': the collector filters hard, so a genuinely
   * idle cluster can be quiet for minutes without anything being wrong.
   */
  silenceMinutes: number;
}

export interface EscalationConfig {
  /** Severity at or below this bypasses first triage entirely. */
  directToSecondAtOrBelowSeverity: number;
  /** Signature regexes that bypass the LLM and resolve as BLOCK. */
  autoBlockPatterns: string[];
}

export interface QuietHours {
  enabled: boolean;
  startHour: number;
  endHour: number;
}

export interface TelegramConfig {
  enabled: boolean;
  botTokenSecret: string;
  chatId: string;
  minSeverity: number;
  quietHours: QuietHours;
}

export interface SmtpConfig {
  enabled: boolean;
  host: string;
  port: number;
  secure: boolean;
  user: string;
  passwordSecret: string;
  from: string;
  /** Send email in parallel with Telegram rather than only on failure. */
  alwaysSend: boolean;
}

export interface OncallConfig {
  enabled: boolean;
  ackTimeoutMinutes: number;
  people: Person[];
  shifts: ShiftEntry[];
  /** Notify these stages' outcomes. */
  notifyOnStages: TriageStage[];
  minSeverity: number;
}

export interface Settings {
  ingest: IngestConfig;
  clusterTelemetry: ClusterTelemetryConfig;
  networkCompass: NetworkCompassConfig;
  detection: DetectionConfig;
  intel: IntelConfig;
  response: ResponseConfig;
  incidents: IncidentConfig;
  firstTriage: FirstTriageConfig;
  secondTriage: SecondTriageConfig;
  escalation: EscalationConfig;
  telegram: TelegramConfig;
  smtp: SmtpConfig;
  oncall: OncallConfig;
  notifications: NotificationConfig;
  site: SiteConfig;
  vpn: VpnConfig;
  remoteAccess: RemoteAccessConfig;
}

/** Which secret fields currently hold a value. Values themselves never leave the server. */
export type SecretPresence = Record<string, boolean>;

// ---------------------------------------------------------------------------
// Detection engine
// ---------------------------------------------------------------------------

export interface MitreRef {
  tacticId: string;
  tactic: string;
  techniqueId: string;
  technique: string;
}

/**
 * `ioc` is an exact indicator match, `rule` a Sigma-style field predicate, and
 * `heuristic` a behaviour scored across several events (beaconing, scanning,
 * volume). They are kept apart because an operator trusts them differently.
 */
export type DetectionKind = "ioc" | "rule" | "heuristic";

export type IocType = "ip" | "domain" | "hash" | "url";

export interface DetectionHit {
  id: string;
  kind: DetectionKind;
  /** Stable identifier, e.g. `AISOC-C2-0002` or `ioc:ip:45.155.205.233`. */
  ruleId: string;
  name: string;
  description: string;
  /** Points contributed to the event's 0–100 detection score. */
  score: number;
  severity: Severity;
  /** Which event field matched, and the value that matched it. */
  field: string;
  value: string;
  /** Rule pack or feed this came from, with its version. */
  origin: string;
  confidence: number;
  mitre: MitreRef[];
}

export type DetectionBand = "clean" | "suspicious" | "malicious";

export interface Detection {
  score: number;
  band: DetectionBand;
  hits: DetectionHit[];
  mitre: MitreRef[];
  engineVersion: string;
  ranAt: string;
  durationMs: number;
}

/** One engine pass, streamed to the analysis panel alongside model calls. */
export interface DetectionRun extends Detection {
  id: string;
  eventId: string;
  alertId: string | null;
  signature: string;
  remoteIp: string;
  assetId: string | null;
}

export interface RulePack {
  id: string;
  name: string;
  kind: "rules" | "ioc" | "mitre";
  version: string;
  entries: number;
  updatedAt: string;
  enabled: boolean;
  origin: string;
}

export interface DetectionConfig {
  enabled: boolean;
  /** Detection score at or above which an event becomes an alert on its own. */
  alertAtScore: number;
  /** Score bands used for the malicious/suspicious labels. */
  maliciousAtScore: number;
  /** Heuristics are the noisiest layer; they can be turned off independently. */
  heuristicsEnabled: boolean;
  iocEnabled: boolean;
  rulesEnabled: boolean;
  /** Rule ids the operator has muted. */
  mutedRuleIds: string[];
}

// ---------------------------------------------------------------------------
// Threat intelligence
// ---------------------------------------------------------------------------

export type IntelProvider = "virustotal" | "abuseipdb" | "local";

export interface IntelSource {
  provider: IntelProvider;
  ok: boolean;
  /** 0–100, higher is worse. Null when the provider had nothing to say. */
  score: number | null;
  detail: string;
  malicious: number | null;
  total: number | null;
  error: string | null;
}

export interface Enrichment {
  indicator: string;
  type: IocType;
  /** Worst score across providers, 0–100. */
  reputation: number;
  sources: IntelSource[];
  country: string | null;
  countryCode: string | null;
  asn: string | null;
  organization: string | null;
  lat: number | null;
  lon: number | null;
  firstSeen: string | null;
  fetchedAt: string;
  cached: boolean;
}

export interface IntelConfig {
  enabled: boolean;
  virusTotalSecret: string;
  abuseIpdbSecret: string;
  /** How long an indicator's verdict is reused before refetching. */
  cacheMinutes: number;
  /** Use the bundled offline reputation set when no API key is configured. */
  useLocalFeed: boolean;
}

// ---------------------------------------------------------------------------
// Response actions
// ---------------------------------------------------------------------------

export type ResponseType =
  | "block_ip"
  | "block_domain"
  | "quarantine_file"
  | "isolate_host"
  | "kill_process";

export type ResponseStatus =
  | "pending_approval"
  | "applied"
  | "failed"
  | "undone"
  | "rejected"
  | "blocked_by_guardrail";

/**
 * manual  — every action waits for a human.
 * guarded — high-confidence actions execute themselves, the rest wait.
 * full    — everything the engine proposes executes.
 */
export type AutonomyMode = "manual" | "guarded" | "full";

export type ResponseOrigin = "engine" | "llm" | "playbook" | "human";

export interface ResponseAction {
  id: string;
  alertId: string | null;
  incidentId: string | null;
  assetId: string | null;
  type: ResponseType;
  /** The IP, domain, path, or pid the action operates on. */
  target: string;
  status: ResponseStatus;
  origin: ResponseOrigin;
  requestedBy: string;
  reason: string;
  autonomy: AutonomyMode;
  /** Why this action did not execute itself, when it did not. */
  guardrail: string | null;
  /** The command that was run, or that would run outside simulation. */
  command: string;
  simulated: boolean;
  playbookId: string | null;
  createdAt: string;
  appliedAt: string | null;
  undoneAt: string | null;
  decidedBy: string | null;
  error: string | null;
}

export interface Guardrails {
  /** Never act on RFC1918 / loopback / link-local addresses. */
  protectPrivateRanges: boolean;
  /** Never act on anything on the allowlist. */
  respectAllowlist: boolean;
  /** In guarded mode, the detection score an action needs to self-execute. */
  autoExecuteAtScore: number;
  /** In guarded mode, the model confidence an action needs to self-execute. */
  autoExecuteAtConfidence: number;
  /** Actions that always need a human, whatever the autonomy setting. */
  alwaysConfirm: ResponseType[];
  /** Cap on self-executed actions in a rolling hour. */
  maxAutoActionsPerHour: number;
}

export interface ResponseConfig {
  enabled: boolean;
  autonomy: AutonomyMode;
  /** `simulate` records the command without running it. */
  execution: "simulate" | "nftables";
  guardrails: Guardrails;
  /** Playbook ids that may run without confirmation. */
  enabledPlaybooks: string[];
}

export interface PlaybookStep {
  type: ResponseType;
  /** Which part of the alert supplies the target. */
  targetFrom: "remote_ip" | "hostname" | "file_path" | "asset" | "process";
  reason: string;
}

export interface Playbook {
  id: string;
  name: string;
  description: string;
  /** Fires when the alert carries any of these detection rule ids or tags. */
  triggerRuleIds: string[];
  triggerTags: string[];
  minScore: number;
  steps: PlaybookStep[];
  enabled: boolean;
}

// ---------------------------------------------------------------------------
// Assets
// ---------------------------------------------------------------------------

export interface AssetProtection {
  realtime: boolean;
  firewall: boolean;
  rulesVersion: string;
  lastScan: string | null;
  agentVersion: string;
}

export interface Asset {
  id: string;
  hostname: string;
  ip: string;
  mac: string;
  os: string;
  kind: "workstation" | "laptop" | "server" | "container";
  owner: string;
  tags: string[];
  online: boolean;
  isolated: boolean;
  lastSeen: string;
  protection: AssetProtection;
  /** 0–100, decayed over time and raised by alerts on this host. */
  riskScore: number;
  openAlerts: number;
  criticalAlerts: number;
  lat: number | null;
  lon: number | null;
}

// ---------------------------------------------------------------------------
// Security incidents
// ---------------------------------------------------------------------------

export type IncidentStatus = "open" | "investigating" | "contained" | "closed";

export type TimelineKind =
  | "alert"
  | "detection"
  | "response"
  | "note"
  | "llm"
  | "notify"
  | "status";

export interface TimelineEntry {
  id: string;
  at: string;
  kind: TimelineKind;
  title: string;
  detail: string;
  refId: string | null;
}

export interface Incident {
  id: string;
  /** Human-facing short id, e.g. `INC-0007`. */
  ref: string;
  title: string;
  status: IncidentStatus;
  severity: Severity;
  /** The shared indicator that grouped these alerts. */
  correlationKey: string;
  correlationBasis: string;
  alertIds: string[];
  assetIds: string[];
  indicators: string[];
  mitre: MitreRef[];
  score: number;
  assignee: string | null;
  narrative: string | null;
  narrativeModel: string | null;
  suggestedResponse: string | null;
  timeline: TimelineEntry[];
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
}

export interface IncidentConfig {
  enabled: boolean;
  /** Alerts within this window sharing an indicator are grouped. */
  correlationWindowMinutes: number;
  groupBy: ("remote_ip" | "asset" | "hash" | "signature" | "scenario")[];
  /** Ask the model for a narrative once an incident has this many alerts. */
  narrateAtAlertCount: number;
}

// ---------------------------------------------------------------------------
// Quarantine, lists, audit
// ---------------------------------------------------------------------------

export type QuarantineKind = "file" | "ip" | "domain" | "process";

export interface QuarantineItem {
  id: string;
  kind: QuarantineKind;
  value: string;
  sha256: string | null;
  assetId: string | null;
  alertId: string | null;
  reason: string;
  status: "held" | "restored" | "deleted";
  sizeBytes: number | null;
  quarantinedAt: string;
  releasedAt: string | null;
  releasedBy: string | null;
  /** The response action that put it here. */
  actionId: string | null;
}

export type ListName = "allow" | "block";

export interface ListEntry {
  id: string;
  list: ListName;
  kind: IocType | "signature";
  value: string;
  note: string;
  addedBy: string;
  addedAt: string;
  expiresAt: string | null;
}

export interface AuditEntry {
  id: string;
  at: string;
  actor: string;
  action: string;
  target: string;
  detail: string;
  ok: boolean;
}

export type NotificationKind =
  | "detection"
  | "response"
  | "incident"
  | "asset"
  | "oncall"
  | "system";

export interface Notification {
  id: string;
  at: string;
  kind: NotificationKind;
  level: "info" | "warning" | "critical";
  title: string;
  body: string;
  read: boolean;
  /** Where clicking it should take the analyst. */
  linkView: string | null;
  linkId: string | null;
}

export interface NotificationConfig {
  /** Per-feature switches for the in-app notification centre. */
  detection: boolean;
  response: boolean;
  incident: boolean;
  asset: boolean;
  oncall: boolean;
  system: boolean;
  /** Also push these kinds to Telegram, not just the notification centre. */
  telegramKinds: NotificationKind[];
}

export interface SiteConfig {
  name: string;
  /** Where the defended network sits, for the threat map. */
  lat: number;
  lon: number;
  /** CIDR-ish prefixes treated as ours; used by guardrails. */
  homeNetworks: string[];
}

// ---------------------------------------------------------------------------
// VPN
// ---------------------------------------------------------------------------

export interface VpnServer {
  id: string;
  country: string;
  countryCode: string;
  city: string;
  /** Endpoint the tunnel dials, and the peer key that authenticates it. */
  host: string;
  port: number;
  publicKey: string;
  /** 0–100. Providers publish this so a client can pick a quiet exit. */
  load: number;
  /** Round-trip time last measured, null until probed. */
  latencyMs: number | null;
  lat: number;
  lon: number;
  tags: ("p2p" | "streaming" | "double-hop" | "obfuscated" | "low-latency")[];
}

/**
 * A real tunnel imported from a provider's WireGuard config, as opposed to the
 * bundled demo catalogue. Keys are never held here — only references into the
 * encrypted secret store.
 */
export interface VpnProfile {
  id: string;
  name: string;
  host: string;
  port: number;
  peerPublicKey: string;
  /** Addresses assigned inside the tunnel, exactly as the provider wrote them. */
  addresses: string[];
  dns: string[];
  mtu: number | null;
  /** AllowedIPs as supplied; the operator's split-tunnel settings can override. */
  allowedIps: string[];
  persistentKeepalive: number | null;
  hasPresharedKey: boolean;
  privateKeySecret: string;
  presharedKeySecret: string | null;
  createdAt: string;
  /** Original filename or provider label, for display. */
  source: string;
}

/** One readiness check, with the exact command that fixes it when it fails. */
export interface VpnCheck {
  id: string;
  label: string;
  ok: boolean;
  detail: string;
  fix: string | null;
}

export type VpnStatus = "disconnected" | "connecting" | "connected" | "reconnecting" | "error";

export interface VpnConnection {
  status: VpnStatus;
  /** Demo catalogue exit, when one is selected. */
  serverId: string | null;
  /** Imported provider profile, when one is selected. Real tunnels use this. */
  profileId: string | null;
  /** Address assigned inside the tunnel. */
  tunnelIp: string | null;
  /** Public address the world now sees us as. */
  exitIp: string | null;
  interfaceName: string;
  connectedAt: string | null;
  lastHandshake: string | null;
  bytesUp: number;
  bytesDown: number;
  /** True when the tunnel was described but never actually brought up. */
  simulated: boolean;
  /** Set when the kill switch is currently holding egress down. */
  killSwitchEngaged: boolean;
  error: string | null;
}

export type SplitTunnelMode = "off" | "include" | "exclude";

export interface VpnConfig {
  enabled: boolean;
  /** Bring the tunnel up as soon as the console starts. */
  autoConnect: boolean;
  /** Reconnect without being asked when a handshake goes stale. */
  reconnectOnDrop: boolean;
  /**
   * Block all egress whenever the tunnel is not up. The whole point of a VPN is
   * that traffic never leaves in the clear; without this, a drop silently
   * de-anonymises everything until someone notices.
   */
  killSwitch: boolean;
  /** Route DNS through the tunnel so lookups cannot leak to the local resolver. */
  dnsLeakProtection: boolean;
  protocol: "wireguard" | "openvpn";
  /** Preferred exit; empty means pick the least-loaded server. */
  preferredCountry: string;
  splitTunnel: {
    mode: SplitTunnelMode;
    /** CIDRs the mode applies to. */
    networks: string[];
  };
  interfaceName: string;
  /** Resolver used inside the tunnel. */
  dns: string;
  /** Reference into the encrypted secret store for the client private key. */
  privateKeySecret: string;
  /** Legacy persisted setting; production ignores it and never invokes sudo. */
  useSudo: boolean;
  /** `simulate` describes the tunnel without touching the network stack. */
  execution: "simulate" | "wg-quick";
}

/**
 * Remote access rides the existing tailnet instead of a second tunnel. When
 * `enabled`, the manager keeps `tailscale` up and the console reachable from
 * other tailnet devices; `allowedLogins` is the allowlist enforced at the
 * trust boundary once a request arrives tagged with a tailnet identity.
 */
export interface RemoteAccessConfig {
  enabled: boolean;
  /** Tailnet login names (`user@domain`) allowed to reach the console remotely. */
  allowedLogins: string[];
}

/** Runtime view of the tailscale daemon, mirror of `tailscale status --json`. */
/** A device on the tailnet, as this host currently sees it. */
export interface TailnetDevice {
  id: string;
  hostname: string;
  dnsName: string;
  os: string;
  tailnetIP: string | null;
  online: boolean;
  /** Tailnet login that owns the device, resolved from the status user map. */
  owner: string | null;
  /** True for the host running this console. */
  self: boolean;
  /** Peer address when traffic flows directly, null while it is relayed. */
  directAddr: string | null;
  /** DERP region carrying the traffic when the path is not direct. */
  relay: string | null;
  rxBytes: number;
  txBytes: number;
  /** Null while the device is online — the daemon reports a zero timestamp. */
  lastSeen: string | null;
  keyExpiry: string | null;
  exitNode: boolean;
  /**
   * Whether this device's owner is on the console's allowlist. A device being
   * on the tailnet is not the same as being allowed in, and the difference is
   * the whole point of the allowlist.
   */
  allowed: boolean;
}

export interface RemoteAccessState {
  /** Binary and daemon reachable. */
  present: boolean;
  /** tailscaled is running and the node is connected to the tailnet. */
  online: boolean;
  /** Raw daemon backend state: `Running`, `NeedsLogin`, `Stopped`, ... */
  backendState: string | null;
  node: string;
  dnsName: string;
  tailnetIP: string | null;
  peerCount: number;
  /** Every device on the tailnet, this host first. */
  devices: TailnetDevice[];
  /** Login URL surfaced when the daemon needs auth. */
  authUrl: string | null;
  /** True when any serve proxy is exposed publicly via Funnel (refused by design). */
  funnelOn: boolean;
  error: string | null;
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

export interface ReportMetric {
  label: string;
  value: number;
  delta: number | null;
  unit: string;
}

export interface Report {
  id: string;
  period: "daily" | "weekly";
  generatedAt: string;
  from: string;
  to: string;
  metrics: ReportMetric[];
  topVectors: { name: string; count: number; severity: Severity }[];
  topTargets: { assetId: string; hostname: string; alerts: number; risk: number }[];
  topIndicators: { value: string; type: IocType; hits: number; reputation: number }[];
  mitreCoverage: { techniqueId: string; technique: string; tactic: string; count: number }[];
  responseSummary: { type: ResponseType; applied: number; pending: number; undone: number }[];
  narrative: string | null;
}

/** Liveness of one eve.json writer behind the ingest source. */
export interface SensorHealth {
  path: string;
  label: string;
  ok: boolean;
  lastWriteAt: string | null;
  detail: string;
}

export interface Stats {
  eventsPerSecond: number;
  totalEvents: number;
  openAlerts: number;
  needsHuman: number;
  llmInFlight: number;
  /** Alerts waiting for a triage slot, and the cap at which overflow is shed. */
  queueDepth: number;
  queueCapacity: number;
  llmTotal: number;
  llmErrors: number;
  tokensUsed: number;
  openIncidents: number;
  uptimeSeconds: number;
  bySeverity: Record<string, number>;
  byStage: Record<TriageStage, number>;
  ingestSource: IngestSource;
  paused: boolean;
  /** One entry per configured eve.json; empty while ingest is seeded. */
  sensors: SensorHealth[];

  /** Detection engine — the deterministic layer that runs before triage. */
  detectionRuns: number;
  detectionHits: number;
  malicious: number;
  suspicious: number;
  /** Response actions waiting on a human because autonomy is not full. */
  pendingActions: number;
  appliedActions: number;
  quarantined: number;
  assetsOnline: number;
  assetsTotal: number;
  assetsIsolated: number;
  atRiskAssets: number;
  openSecurityIncidents: number;
  unreadNotifications: number;
  autonomy: AutonomyMode;
  engineVersion: string;
  vpnStatus: VpnStatus;
  vpnCountry: string | null;
  vpnKillSwitch: boolean;
}

export interface Snapshot {
  events: SecurityEvent[];
  networkFlows: NetworkFlow[];
  compass: CompassSummary;
  compassReview: CompassReview | null;
  alerts: Alert[];
  llmCalls: LlmCall[];
  detections: DetectionRun[];
  pages: OncallIncident[];
  incidents: Incident[];
  actions: ResponseAction[];
  assets: Asset[];
  quarantine: QuarantineItem[];
  lists: ListEntry[];
  audit: AuditEntry[];
  notifications: Notification[];
  rulePacks: RulePack[];
  playbooks: Playbook[];
  vpn: VpnConnection;
  vpnServers: VpnServer[];
  vpnProfiles: VpnProfile[];
  remoteAccess: RemoteAccessState;
  stats: Stats;
  settings: Settings;
  secrets: SecretPresence;
}

export interface PentestTarget {
  id: string;
  label: string;
  url: string;
  note?: string;
  reachable: boolean;
}

export type PentestProfile = "baseline" | "full" | "nuclei";
export type PentestStatus = "running" | "done" | "cancelled" | "error";
export type PentestSeverity = "high" | "medium" | "low" | "info";

export interface PentestFinding {
  id: string;
  name: string;
  severity: PentestSeverity;
  instances: number;
  description: string;
  solution: string;
  reference: string;
  sampleUrl: string | null;
}

export interface PentestRun {
  id: string;
  target: string;
  profile: PentestProfile;
  status: PentestStatus;
  startedAt: string;
  finishedAt: string | null;
  actor: string;
  durationMs: number | null;
  summary: { high: number; medium: number; low: number; info: number };
  findings: PentestFinding[];
  error: string | null;
}

/** Frames streamed over /ws/pentest for a single run. */
export type PentestFrame = { type: "log"; line: string } | { type: "status"; run: PentestRun };

export type ServerMessage =
  | ({ type: "snapshot" } & Snapshot)
  | { type: "event"; event: SecurityEvent }
  | { type: "network-flow"; flow: NetworkFlow }
  | { type: "compass"; summary: CompassSummary }
  | { type: "compass-review"; review: CompassReview | null }
  | { type: "alert"; alert: Alert }
  | { type: "llm"; call: LlmCall }
  | { type: "llm-clear"; stages: LlmStageName[] }
  | { type: "detection"; detection: DetectionRun }
  | { type: "page"; page: OncallIncident }
  | { type: "incident"; incident: Incident }
  | { type: "action"; action: ResponseAction }
  | { type: "asset"; asset: Asset }
  | { type: "quarantine"; item: QuarantineItem }
  | { type: "lists"; entries: ListEntry[] }
  | { type: "audit"; entry: AuditEntry }
  | { type: "notification"; notification: Notification }
  | { type: "notifications-read"; ids: string[] }
  | { type: "rulePacks"; packs: RulePack[] }
  | { type: "playbooks"; playbooks: Playbook[] }
  | {
      type: "vpn";
      connection: VpnConnection;
      servers: VpnServer[];
      profiles: VpnProfile[];
    }
  | { type: "remoteaccess"; state: RemoteAccessState }
  | { type: "stats"; stats: Stats }
  | { type: "settings"; settings: Settings; secrets: SecretPresence }
  | { type: "toast"; level: "info" | "success" | "error"; message: string };
