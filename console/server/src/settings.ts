import { existsSync, readFileSync } from "node:fs";
import { DEFAULT_SETTINGS, type Settings } from "@aisoc/shared";
import { z } from "zod";
import { writePrivateAtomic } from "./atomic.js";
import { SETTINGS_FILE } from "./paths.js";

const provider = z.enum(["openai-compatible", "anthropic", "codex-proxy"]);
const verdict = z.enum(["BLOCK", "WATCH", "IGNORE"]);
const stage = z.enum(["pending", "first_triage", "second_triage", "resolved", "needs_human"]);

const stageConfig = {
  provider,
  endpoint: z.string().max(500),
  model: z.string().max(200),
  temperature: z.number().min(0).max(2),
  maxTokens: z.number().int().min(64).max(128_000),
  timeoutMs: z.number().int().min(1_000).max(600_000),
  apiKeySecret: z.string().max(100),
};

const hour = z.number().int().min(0).max(23);
const severity = z.number().int().min(1).max(4);
const responseType = z.enum([
  "block_ip",
  "block_domain",
  "quarantine_file",
  "isolate_host",
  "kill_process",
]);
const notificationKind = z.enum(["detection", "response", "incident", "asset", "oncall", "system"]);

export const settingsSchema = z.object({
  ingest: z.object({
    source: z.enum(["seed", "eve", "host"]),
    evePath: z.string().max(500),
    eventsPerSecond: z.number().min(0.1).max(50),
    maxTriageSeverity: severity,
    paused: z.boolean(),
  }),
  clusterTelemetry: z.object({
    enabled: z.boolean(),
    spoolPath: z.string().max(500),
    silenceMinutes: z.number().int().min(1).max(180),
  }),
  networkCompass: z.object({
    enabled: z.boolean(),
    paused: z.boolean(),
    insightsEnabled: z.boolean(),
    aiReviewEnabled: z.boolean(),
    beaconDetectionEnabled: z.boolean(),
    beaconSuppressions: z.array(z.string().min(1).max(300)).max(500),
    rawRetentionHours: z.number().int().min(1).max(168),
    historyDays: z.number().int().min(0).max(365),
    excludedDomains: z
      .array(
        z
          .string()
          .trim()
          .toLowerCase()
          .min(1)
          .max(253)
          .regex(/^[a-z0-9.-]+$/)
          .refine((domain) => !domain.includes(".."), "invalid domain"),
      )
      .max(500),
  }),
  detection: z.object({
    enabled: z.boolean(),
    alertAtScore: z.number().int().min(1).max(100),
    maliciousAtScore: z.number().int().min(1).max(100),
    heuristicsEnabled: z.boolean(),
    iocEnabled: z.boolean(),
    rulesEnabled: z.boolean(),
    mutedRuleIds: z.array(z.string().max(100)).max(200),
  }),
  intel: z.object({
    enabled: z.boolean(),
    virusTotalSecret: z.string().max(100),
    abuseIpdbSecret: z.string().max(100),
    cacheMinutes: z.number().int().min(1).max(10_080),
    useLocalFeed: z.boolean(),
  }),
  response: z.object({
    enabled: z.boolean(),
    autonomy: z.enum(["manual", "guarded", "full"]),
    execution: z.enum(["simulate", "nftables"]),
    guardrails: z.object({
      protectPrivateRanges: z.boolean(),
      respectAllowlist: z.boolean(),
      autoExecuteAtScore: z.number().int().min(0).max(100),
      autoExecuteAtConfidence: z.number().min(0).max(1),
      alwaysConfirm: z.array(responseType).max(5),
      maxAutoActionsPerHour: z.number().int().min(0).max(1_000),
    }),
    enabledPlaybooks: z.array(z.string().max(100)).max(50),
  }),
  incidents: z.object({
    enabled: z.boolean(),
    correlationWindowMinutes: z.number().int().min(1).max(1_440),
    groupBy: z.array(z.enum(["remote_ip", "asset", "hash", "signature", "scenario"])).max(5),
    narrateAtAlertCount: z.number().int().min(1).max(50),
  }),
  firstTriage: z.object({
    ...stageConfig,
    autoCloseConfidence: z.number().min(0).max(1),
    escalateBelowConfidence: z.number().min(0).max(1),
    escalateCategories: z.array(z.string().max(200)).max(50),
    escalateAtOrBelowSeverity: z.number().int().min(0).max(4),
    escalateVerdicts: z.array(verdict).max(3),
  }),
  secondTriage: z.object({
    ...stageConfig,
    autoResolve: z.boolean(),
    autoResolveConfidence: z.number().min(0).max(1),
    batchSize: z.number().int().min(1).max(20),
    batchLingerMs: z.number().int().min(0).max(60_000),
  }),
  escalation: z.object({
    directToSecondAtOrBelowSeverity: z.number().int().min(0).max(4),
    autoBlockPatterns: z.array(z.string().max(300)).max(50),
  }),
  telegram: z.object({
    enabled: z.boolean(),
    botTokenSecret: z.string().max(100),
    chatId: z.string().max(100),
    minSeverity: severity,
    quietHours: z.object({ enabled: z.boolean(), startHour: hour, endHour: hour }),
  }),
  smtp: z.object({
    enabled: z.boolean(),
    host: z.string().max(300),
    port: z.number().int().min(1).max(65_535),
    secure: z.boolean(),
    user: z.string().max(300),
    passwordSecret: z.string().max(100),
    from: z.string().max(300),
    alwaysSend: z.boolean(),
  }),
  oncall: z.object({
    enabled: z.boolean(),
    ackTimeoutMinutes: z.number().min(0.1).max(1440),
    people: z
      .array(
        z.object({
          id: z.string().max(100),
          name: z.string().max(200),
          telegramId: z.string().max(100),
          email: z.string().max(300),
          active: z.boolean(),
        }),
      )
      .max(100),
    shifts: z
      .array(
        z.object({
          id: z.string().max(100),
          personId: z.string().max(100),
          days: z.array(z.number().int().min(0).max(6)).max(7),
          startHour: hour,
          endHour: hour,
        }),
      )
      .max(200),
    notifyOnStages: z.array(stage).max(5),
    minSeverity: severity,
  }),
  notifications: z.object({
    detection: z.boolean(),
    response: z.boolean(),
    incident: z.boolean(),
    asset: z.boolean(),
    oncall: z.boolean(),
    system: z.boolean(),
    telegramKinds: z.array(notificationKind).max(6),
  }),
  vpn: z.object({
    enabled: z.boolean(),
    autoConnect: z.boolean(),
    reconnectOnDrop: z.boolean(),
    killSwitch: z.boolean(),
    dnsLeakProtection: z.boolean(),
    protocol: z.enum(["wireguard", "openvpn"]),
    preferredCountry: z.string().max(60),
    splitTunnel: z.object({
      mode: z.enum(["off", "include", "exclude"]),
      networks: z.array(z.string().max(64)).max(64),
    }),
    interfaceName: z
      .string()
      .min(1)
      .max(15)
      // Becomes an argv entry for wg-quick, so the shape is constrained here.
      .regex(/^[a-zA-Z0-9_-]+$/, "interface names are letters, digits, dash, underscore"),
    dns: z.string().max(64),
    privateKeySecret: z.string().max(100),
    useSudo: z.boolean(),
    execution: z.enum(["simulate", "wg-quick"]),
  }),
  remoteAccess: z.object({
    enabled: z.boolean(),
    allowedLogins: z.array(z.string().max(120)).max(64),
  }),
  site: z.object({
    name: z.string().max(120),
    lat: z.number().min(-90).max(90),
    lon: z.number().min(-180).max(180),
    homeNetworks: z.array(z.string().max(64)).max(20),
  }),
});

/**
 * The validator is a hand-written mirror of `Settings`, and drift between them
 * is silent at runtime — a provider added to the type but not the enum makes
 * every settings save fail validation. This fails the build instead.
 */
type Exact<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never;
const _schemaMatchesSettingsType: Exact<z.infer<typeof settingsSchema>, Settings> = true;
void _schemaMatchesSettingsType;

/** Recursive merge so a partial PATCH from the UI keeps untouched branches. */
function merge<T>(base: T, patch: unknown): T {
  if (patch === null || typeof patch !== "object" || Array.isArray(patch)) {
    return (patch === undefined ? base : patch) as T;
  }
  const out: Record<string, unknown> = { ...(base as Record<string, unknown>) };
  for (const [key, value] of Object.entries(patch as Record<string, unknown>)) {
    if (!(key in out)) continue;
    out[key] = merge(out[key], value);
  }
  return out as T;
}

let current: Settings = load();

function load(): Settings {
  const isDemo = process.env.AISOC_DEMO === "1" || process.env.AISOC_DEMO === "true";
  if (!existsSync(SETTINGS_FILE)) {
    const s = structuredClone(DEFAULT_SETTINGS);
    if (isDemo) {
      s.ingest.source = "seed";
      s.ingest.paused = false;
    }
    return s;
  }
  try {
    const parsed = settingsSchema.safeParse(
      merge(DEFAULT_SETTINGS, JSON.parse(readFileSync(SETTINGS_FILE, "utf8"))),
    );
    const s = parsed.success ? parsed.data : structuredClone(DEFAULT_SETTINGS);
    if (isDemo) {
      s.ingest.source = "seed";
      s.ingest.paused = false;
    }
    return s;
  } catch {
    const s = structuredClone(DEFAULT_SETTINGS);
    if (isDemo) {
      s.ingest.source = "seed";
      s.ingest.paused = false;
    }
    return s;
  }
}

export function reloadSettings(): Settings {
  current = load();
  return current;
}

export function getSettings(): Settings {
  return current;
}

export function updateSettings(patch: unknown): Settings {
  current = settingsSchema.parse(merge(current, patch));
  writePrivateAtomic(SETTINGS_FILE, JSON.stringify(current, null, 2));
  return current;
}
