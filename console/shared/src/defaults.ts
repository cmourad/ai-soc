import type { RemoteAccessState, Settings } from "./types.js";

/**
 * Tier 1 is the GPU-resident 27B (~2s per verdict); tier 2 escalates to the
 * codex CLI behind the local openaiserver proxy, which constrains the verdict
 * shape at the sampler. Swap `secondTriage` to the anthropic provider to put a
 * cloud model behind escalation instead.
 */
export const DEFAULT_SETTINGS: Settings = {
  ingest: {
    source: "seed",
    // Relative paths resolve against the repo root, not the console directory.
    evePath: "suricata/logs/eve.json,suricata/logs-vpn/eve.json",
    // Sized so triage keeps up on this box; raise it to watch the backlog shed.
    eventsPerSecond: 0.8,
    maxTriageSeverity: 2,
    paused: false,
  },
  clusterTelemetry: {
    // Off until the collector unit is installed; a missing spool would
    // otherwise report a dead sensor on every desktop that has no cluster.
    enabled: false,
    spoolPath: "/var/lib/aisoc-host-events/cluster-events.jsonl",
    silenceMinutes: 15,
  },
  networkCompass: {
    // Ordinary network activity is more private than a security alert. The
    // operator must explicitly opt in from the Compass screen.
    enabled: false,
    paused: false,
    insightsEnabled: true,
    // The only control that lets Compass data leave the machine. Off until the
    // operator turns it on, and it only ever fires on an explicit request.
    aiReviewEnabled: false,
    beaconDetectionEnabled: true,
    beaconSuppressions: [],
    rawRetentionHours: 24,
    // Per-destination daily totals only. Without a memory longer than the raw
    // window, novelty cannot be answered at all.
    historyDays: 30,
    excludedDomains: [],
  },
  detection: {
    enabled: true,
    // A single high-confidence IoC scores 45, so one hit alone does not open an
    // alert — corroboration does. Tuned against the seeded scenarios.
    alertAtScore: 40,
    maliciousAtScore: 70,
    heuristicsEnabled: true,
    iocEnabled: true,
    rulesEnabled: true,
    mutedRuleIds: [],
  },
  intel: {
    enabled: true,
    virusTotalSecret: "intel.virustotal",
    abuseIpdbSecret: "intel.abuseipdb",
    cacheMinutes: 60,
    useLocalFeed: true,
  },
  response: {
    enabled: true,
    // Starts where an operator can see every proposal before it fires. Guarded
    // is the setting this console is designed around; full is for lab use.
    autonomy: "manual",
    execution: "simulate",
    guardrails: {
      protectPrivateRanges: true,
      respectAllowlist: true,
      autoExecuteAtScore: 70,
      autoExecuteAtConfidence: 0.85,
      alwaysConfirm: ["isolate_host"],
      maxAutoActionsPerHour: 20,
    },
    enabledPlaybooks: ["pb-c2-containment", "pb-ransomware", "pb-exfil"],
  },
  incidents: {
    enabled: true,
    correlationWindowMinutes: 30,
    groupBy: ["scenario", "remote_ip", "asset", "hash"],
    narrateAtAlertCount: 2,
  },
  firstTriage: {
    provider: "openai-compatible",
    endpoint: "http://127.0.0.1:8082/v1/chat/completions",
    model: "Qwen3.6-27B-MTP-Q4_K_S",
    temperature: 0.1,
    // The verdict is three short fields; the budget only needs to cover that.
    maxTokens: 512,
    // Measured: ~2s per verdict on GPU, so this is slack, not a target.
    timeoutMs: 120_000,
    apiKeySecret: "",
    autoCloseConfidence: 0.85,
    escalateBelowConfidence: 0.7,
    escalateCategories: [
      "Attempted Administrator Privilege Gain",
      "Web Application Attack",
      "A Network Trojan was Detected",
      "Malware Command and Control Activity Detected",
    ],
    escalateAtOrBelowSeverity: 1,
    // With the 27B on tier 1 — which scored 10/10 with zero false-ignores on
    // scripts/eval_tiers.py, including the prompt-injection case — a confident
    // IGNORE can close here. Only BLOCK buys a second opinion, since that is
    // the verdict that would drive enforcement.
    escalateVerdicts: ["BLOCK"],
  },
  secondTriage: {
    provider: "codex-proxy",
    endpoint: "http://127.0.0.1:8080/v1/chat/completions",
    model: "gpt-5.6-luna",
    // Ignored by the proxy — codex takes no sampling parameters.
    temperature: 0,
    maxTokens: 1024,
    // The proxy's own RUN_TIMEOUT_MS defaults to 300s; give up no sooner than it does.
    timeoutMs: 300_000,
    apiKeySecret: "codexProxy.token",
    autoResolve: true,
    autoResolveConfidence: 0.8,
    // Most of a codex call is process spawn, so several alerts cost barely more
    // than one. Kept small so a single poisoned alert has a bounded blast
    // radius; set to 1 to restore strict per-alert isolation.
    batchSize: 4,
    batchLingerMs: 2_000,
  },
  escalation: {
    directToSecondAtOrBelowSeverity: 1,
    autoBlockPatterns: ["^ET (DROP|CINS|COMPROMISED) "],
  },
  telegram: {
    enabled: false,
    botTokenSecret: "telegram.botToken",
    chatId: "",
    minSeverity: 2,
    quietHours: { enabled: false, startHour: 23, endHour: 7 },
  },
  smtp: {
    enabled: false,
    host: "",
    port: 587,
    secure: false,
    user: "",
    passwordSecret: "smtp.password",
    from: "",
    alwaysSend: false,
  },
  oncall: {
    enabled: false,
    ackTimeoutMinutes: 5,
    people: [],
    shifts: [],
    notifyOnStages: ["needs_human"],
    minSeverity: 2,
  },
  notifications: {
    detection: true,
    response: true,
    incident: true,
    asset: true,
    oncall: true,
    system: true,
    // Only the two that mean something happened on the estate go out of band.
    telegramKinds: ["incident", "response"],
  },
  vpn: {
    enabled: false,
    autoConnect: false,
    reconnectOnDrop: true,
    // On by default so that enabling the VPN at all cannot quietly leave
    // traffic in the clear the first time a tunnel drops.
    killSwitch: true,
    dnsLeakProtection: true,
    protocol: "wireguard",
    preferredCountry: "",
    splitTunnel: { mode: "exclude", networks: ["192.0.2.0/24", "10.0.0.0/8"] },
    interfaceName: "aisoc0",
    dns: "10.64.0.1",
    privateKeySecret: "vpn.privateKey",
    // Retained for settings compatibility; production never invokes sudo.
    useSudo: false,
    // Describes the tunnel without touching routing until an operator opts in.
    execution: "simulate",
  },
  remoteAccess: {
    // Trust boundary is only locked down when an operator explicitly turns it on.
    enabled: false,
    allowedLogins: [],
  },
  site: {
    name: "Lab environment",
    lat: 0,
    lon: 0,
    // A tunnel handed a globally-routable v6 prefix looks external to every
    // range test there is, so the site's own prefix has to be declared.
    homeNetworks: ["192.0.2.0/24", "10.0.0.0/8", "2001:db8::/48"],
  },
};

export const SEVERITY_LABEL: Record<number, string> = {
  1: "critical",
  2: "high",
  3: "medium",
  4: "low",
};

export const EXPORT_KINDS = [
  "alerts",
  "incidents",
  "actions",
  "audit",
  "quarantine",
  "assets",
] as const;

export type ExportKind = (typeof EXPORT_KINDS)[number];

export function isExportKind(value: string): value is ExportKind {
  return (EXPORT_KINDS as readonly string[]).includes(value);
}

/**
 * The state a host reports before tailscale has been looked at, and the state
 * it resets to. Startup and reset must agree or a restart shows a tunnel the
 * daemon never had.
 */
export function blankRemoteAccessState(): RemoteAccessState {
  return {
    present: false,
    online: false,
    backendState: null,
    node: "",
    dnsName: "",
    tailnetIP: null,
    peerCount: 0,
    devices: [],
    authUrl: null,
    funnelOn: false,
    error: null,
  };
}
