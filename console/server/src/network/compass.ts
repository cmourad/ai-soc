import type {
  CompassCategory,
  CompassDestination,
  CompassInsight,
  CompassSummary,
  DomainConfidence,
  DomainSource,
  FlowDirection,
  InsightStatus,
  NetworkFlow,
  TrafficClass,
} from "@aisoc/shared";
import {
  addressKey,
  formatBytes,
  inNetwork,
  ipv4Number,
  isLocal as isLocalToSite,
  sameAddress,
  windowLabel,
} from "@aisoc/shared";
import { geolocate } from "../intel/geo.js";

type EveRecord = {
  timestamp?: unknown;
  event_type?: unknown;
  flow_id?: unknown;
  iface?: unknown;
  in_iface?: unknown;
  src_ip?: unknown;
  src_port?: unknown;
  dest_ip?: unknown;
  dest_port?: unknown;
  proto?: unknown;
  app_proto?: unknown;
  tls?: { sni?: unknown };
  http?: { hostname?: unknown };
  dns?: {
    type?: unknown;
    rrname?: unknown;
    query?: { rrname?: unknown }[];
    answers?: { rrname?: unknown; rdata?: unknown }[];
  };
  flow?: {
    start?: unknown;
    end?: unknown;
    state?: unknown;
    bytes_toserver?: unknown;
    bytes_toclient?: unknown;
    pkts_toserver?: unknown;
    pkts_toclient?: unknown;
  };
};

type HostObservation = { hostname: string; domain: string; source: DomainSource };

const MAX_PENDING_HOSTS = 10_000;
const MAX_RESOLVED_ADDRESSES = 40_000;
/** A name learned from DNS stops describing a CDN address quickly. */
const RESOLVED_ADDRESS_TTL_MS = 6 * 3_600_000;

const MULTIPART_SUFFIXES = new Set([
  "co.uk",
  "com.au",
  "co.jp",
  "co.nz",
  "com.br",
  "com.mx",
  "co.in",
  "com.sg",
]);

/**
 * Pseudo-domains that only ever appear as protocol machinery. Attributing a
 * connection to them told the operator nothing and crowded out real sites.
 */
const NON_DESTINATION_TLDS = new Set([
  "arpa",
  "local",
  "localdomain",
  "internal",
  "lan",
  "invalid",
]);
const NON_DESTINATION_DOMAINS = new Set(["use-application-dns.net", "home.arpa", "resolver.arpa"]);

/** Ports and protocols a person never chooses. Hidden from the default view. */
const INFRASTRUCTURE_PROTOS = new Set(["dns", "ntp", "dhcp", "krb5", "ikev2", "mdns", "llmnr"]);
const INFRASTRUCTURE_PORTS = new Set([53, 67, 68, 123, 137, 138, 1900, 3702, 5353, 5355]);
/** Encrypted DNS rides port 443, so the port test alone reads it as browsing. */
const RESOLVER_DOMAINS = new Set([
  "cloudflare-dns.com",
  "dns.google",
  "dns.quad9.net",
  "dns.nextdns.io",
  "doh.opendns.com",
  "mullvad.net",
]);
/** The same resolvers dialled by address, where no name is ever observed. */
const RESOLVER_ADDRESSES = new Set(
  [
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    "2620:fe::fe",
  ]
    .map((address) => addressKey(address))
    .filter((key): key is string => key !== null),
);

const CATEGORY_DOMAINS: Record<string, readonly string[]> = {
  "artificial-intelligence": [
    "anthropic.com",
    "chatgpt.com",
    "claude.ai",
    "huggingface.co",
    "ollama.com",
    "openai.com",
    "perplexity.ai",
    "replicate.com",
  ],
  "software-development": [
    "github.com",
    "githubusercontent.com",
    "gitlab.com",
    "npmjs.com",
    "pypi.org",
    "stackoverflow.com",
    "supabase.co",
    "vercel.com",
  ],
  "video-streaming": ["googlevideo.com", "netflix.com", "vimeo.com", "ytimg.com", "youtube.com"],
  messaging: ["discord.com", "signal.org", "slack.com", "telegram.org", "whatsapp.net"],
  "learning-research": ["arxiv.org", "coursera.org", "khanacademy.org", "wikipedia.org"],
  "design-creativity": ["adobe.com", "canva.com", "figma.com"],
  "music-audio": ["bandcamp.com", "soundcloud.com", "spotify.com"],
  gaming: ["itch.io", "steamcommunity.com", "steampowered.com", "twitch.tv"],
};

const CATEGORY_LABELS: Record<string, string> = {
  "artificial-intelligence": "AI assistants",
  "software-development": "Software development",
  "video-streaming": "Video streaming",
  messaging: "Messaging",
  "learning-research": "Learning & research",
  "design-creativity": "Design & creativity",
  "music-audio": "Music & audio",
  gaming: "Gaming",
};

const DOMAIN_TO_CATEGORY = new Map<string, string>(
  Object.entries(CATEGORY_DOMAINS).flatMap(([category, domains]) =>
    domains.map((domain) => [domain, category] as const),
  ),
);

/**
 * Rejects rather than repairs. Filtering illegal characters out silently turned
 * `foo bar.com` into the unrelated real domain `foobar.com`.
 */
function cleanString(value: unknown, max: number): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim().toLowerCase();
  if (!trimmed || trimmed.length > max) return null;
  for (const char of trimmed) {
    const code = char.codePointAt(0)!;
    if (code < 0x21 || code === 0x7f) return null;
  }
  return trimmed;
}

function number(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : 0;
}

function timestamp(value: unknown, fallback: string): string {
  if (typeof value !== "string") return fallback;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? fallback : date.toISOString();
}

function isLocal(
  ip: string,
  homeNetworks: readonly string[],
  localAddresses: readonly string[],
): boolean {
  return (
    isLocalToSite(ip) ||
    localAddresses.some((address) => sameAddress(ip, address)) ||
    homeNetworks.some((network) => inNetwork(ip, network))
  );
}

function directionFor(
  srcIp: string,
  destIp: string,
  homeNetworks: readonly string[],
  localAddresses: readonly string[],
): { direction: FlowDirection; localIsSource: boolean } {
  const sourceLocal = isLocal(srcIp, homeNetworks, localAddresses);
  const destinationLocal = isLocal(destIp, homeNetworks, localAddresses);
  if (sourceLocal && destinationLocal) return { direction: "internal", localIsSource: true };
  if (sourceLocal) return { direction: "outbound", localIsSource: true };
  if (destinationLocal) return { direction: "inbound", localIsSource: false };
  return { direction: "unknown", localIsSource: true };
}

/** Bounded, lowercase, at most four labels — enough to identify, not to profile. */
export function normalizeHostname(input: string): string | null {
  const hostname = input.toLowerCase().replace(/^\.+|\.+$/g, "");
  if (!hostname || hostname.length > 253 || !/^[a-z0-9.-]+$/.test(hostname)) return null;
  if (hostname.includes("..") || ipv4Number(hostname) !== null) return null;
  const labels = hostname.split(".");
  if (labels.some((label) => label.length === 0 || label.length > 63)) return null;
  return labels.slice(-4).join(".");
}

export function registrableDomain(input: string): string | null {
  const hostname = normalizeHostname(input);
  if (!hostname) return null;
  const labels = hostname.split(".");
  if (labels.length < 2) return null;
  const tld = labels.at(-1)!;
  if (NON_DESTINATION_TLDS.has(tld)) return null;
  const pair = labels.slice(-2).join(".");
  const domain =
    MULTIPART_SUFFIXES.has(pair) && labels.length >= 3 ? labels.slice(-3).join(".") : pair;
  return NON_DESTINATION_DOMAINS.has(domain) ? null : domain;
}

export function categoryForDomain(domain: string | null): string | null {
  return domain ? (DOMAIN_TO_CATEGORY.get(domain) ?? null) : null;
}

export function categoryLabel(category: string | null): string | null {
  return category ? (CATEGORY_LABELS[category] ?? category) : null;
}

function classify(
  appProto: string | null,
  remoteIp: string,
  remotePort: number,
  direction: FlowDirection,
  domain: string | null,
  isTransport: boolean,
): TrafficClass {
  // The tunnel carries the same bytes the tunnel interface reports again as
  // real destinations. Counting both doubles every total on this host, so the
  // encrypted leg is transport, not a place the operator visited.
  if (isTransport) return "infrastructure";
  if (appProto && INFRASTRUCTURE_PROTOS.has(appProto)) return "infrastructure";
  if (INFRASTRUCTURE_PORTS.has(remotePort)) return "infrastructure";
  if (domain && RESOLVER_DOMAINS.has(domain)) return "infrastructure";
  const key = addressKey(remoteIp);
  if (key && RESOLVER_ADDRESSES.has(key)) return "infrastructure";
  if (direction === "internal") return "local";
  if (remotePort === 80 || remotePort === 443 || remotePort === 8080 || remotePort === 8443) {
    return "web";
  }
  return "other";
}

/**
 * The host the client named on this connection. DNS query names are excluded on
 * purpose: the destination of a DNS packet is the resolver, so recording the
 * query as the destination both misattributed the flow and wrote a browsing
 * history into the ledger. Query names are used only to build the address map
 * below, which then labels the real connection.
 */
function assertedHost(raw: EveRecord): HostObservation | null {
  const candidates: [unknown, DomainSource][] = [
    [raw.tls?.sni, "tls"],
    [raw.http?.hostname, "http"],
  ];
  for (const [value, source] of candidates) {
    const cleaned = cleanString(value, 253);
    const hostname = cleaned ? normalizeHostname(cleaned) : null;
    const domain = hostname ? registrableDomain(hostname) : null;
    if (hostname && domain) return { hostname, domain, source };
  }
  return null;
}

/** Correlates protocol records with the terminal EVE flow record by flow_id. */
export class EveFlowCorrelator {
  readonly #hosts = new Map<string, HostObservation>();
  readonly #resolved = new Map<string, { host: HostObservation; at: number }>();

  /** Learns address→name from DNS answers so unnamed IP flows can be labelled. */
  #learnFromDns(record: EveRecord, at: number): void {
    const answers = record.dns?.answers;
    if (record.dns?.type !== "answer" || !Array.isArray(answers)) return;
    for (const answer of answers.slice(0, 20)) {
      const address = cleanString(answer?.rdata, 45);
      const key = address ? addressKey(address) : null;
      const name = cleanString(answer?.rrname ?? record.dns?.rrname, 253);
      const hostname = name ? normalizeHostname(name) : null;
      const domain = hostname ? registrableDomain(hostname) : null;
      if (!key || !hostname || !domain) continue;
      this.#resolved.delete(key);
      this.#resolved.set(key, { host: { hostname, domain, source: "dns" }, at });
      while (this.#resolved.size > MAX_RESOLVED_ADDRESSES) {
        const oldest = this.#resolved.keys().next().value as string | undefined;
        if (!oldest) break;
        this.#resolved.delete(oldest);
      }
    }
  }

  #lookupResolved(ip: string, at: number): HostObservation | null {
    const key = addressKey(ip);
    const entry = key ? this.#resolved.get(key) : null;
    if (!entry) return null;
    if (at - entry.at > RESOLVED_ADDRESS_TTL_MS) {
      this.#resolved.delete(key!);
      return null;
    }
    return entry.host;
  }

  consume(
    raw: unknown,
    sensor: string,
    homeNetworks: readonly string[],
    localAddresses: readonly string[] = [],
    /** Addresses that carry a tunnel rather than terminate a conversation. */
    transportAddresses: readonly string[] = [],
  ): NetworkFlow | null {
    if (!raw || typeof raw !== "object") return null;
    const record = raw as EveRecord;
    const flowId = String(record.flow_id ?? "");
    if (!flowId) return null;
    // Two EVE streams (physical and VPN) are tailed at once and their flow ids
    // are independent sequences, so the cache must not be shared across them.
    const cacheKey = `${sensor}:${flowId}`;
    const now = timestamp(record.timestamp, new Date().toISOString());
    const nowMs = Date.parse(now);

    this.#learnFromDns(record, nowMs);

    const asserted = assertedHost(record);
    if (asserted) {
      this.#hosts.delete(cacheKey);
      this.#hosts.set(cacheKey, asserted);
      while (this.#hosts.size > MAX_PENDING_HOSTS) {
        const oldest = this.#hosts.keys().next().value as string | undefined;
        if (!oldest) break;
        this.#hosts.delete(oldest);
      }
    }
    if (record.event_type !== "flow" || !record.flow) return null;

    const srcIp = cleanString(record.src_ip, 45) ?? "0.0.0.0";
    const destIp = cleanString(record.dest_ip, 45) ?? "0.0.0.0";
    const relation = directionFor(srcIp, destIp, homeNetworks, localAddresses);
    const localIsSource = relation.localIsSource;
    const remoteIp = localIsSource ? destIp : srcIp;
    const remotePort = number(localIsSource ? record.dest_port : record.src_port);
    const appProto = cleanString(record.app_proto, 32);

    const pending = asserted ?? this.#hosts.get(cacheKey) ?? null;
    this.#hosts.delete(cacheKey);
    const named = pending ?? this.#lookupResolved(remoteIp, nowMs);
    const isTransport = transportAddresses.some((address) => sameAddress(remoteIp, address));
    const trafficClass = classify(
      appProto,
      remoteIp,
      remotePort,
      relation.direction,
      named?.domain ?? null,
      isTransport,
    );
    // A resolver conversation is about a name, not to it.
    const host = trafficClass === "infrastructure" ? null : named;
    const confidence: DomainConfidence = !host
      ? "unknown"
      : host.source === "dns"
        ? "inferred"
        : "asserted";

    const startedAt = timestamp(record.flow.start, now);
    const toServerBytes = number(record.flow.bytes_toserver);
    const toClientBytes = number(record.flow.bytes_toclient);
    const toServerPackets = number(record.flow.pkts_toserver);
    const toClientPackets = number(record.flow.pkts_toclient);

    const attribution = geolocate(remoteIp);
    return {
      id: `${sensor}:${flowId}:${startedAt}`,
      flowId,
      sensor,
      startedAt,
      endedAt: timestamp(record.flow.end, now),
      updatedAt: now,
      localIp: localIsSource ? srcIp : destIp,
      localPort: number(localIsSource ? record.src_port : record.dest_port),
      remoteIp,
      remotePort,
      direction: relation.direction,
      trafficClass,
      proto: cleanString(record.proto, 16)?.toUpperCase() ?? "UNKNOWN",
      appProto,
      hostname: host?.hostname ?? null,
      domain: host?.domain ?? null,
      domainSource: host?.source ?? null,
      domainConfidence: confidence,
      country: attribution?.countryCode ?? null,
      asn: attribution?.asn ?? null,
      organization: attribution?.organization ?? null,
      bytesUp: localIsSource ? toServerBytes : toClientBytes,
      bytesDown: localIsSource ? toClientBytes : toServerBytes,
      packetsUp: localIsSource ? toServerPackets : toClientPackets,
      packetsDown: localIsSource ? toClientPackets : toServerPackets,
      state: cleanString(record.flow.state, 40),
      category: categoryForDomain(host?.domain ?? null),
      processName: null,
    };
  }
}

export type DomainHistory = Record<string, { days: number; firstDay: string }>;
export type InsightFeedback = Record<
  string,
  { status: InsightStatus; snoozedUntil: string | null }
>;

export interface CompassConfig {
  enabled: boolean;
  paused: boolean;
  insightsEnabled: boolean;
  windowHours: number;
}

/**
 * Insights are facts the operator could verify from the table below them. They
 * are deliberately not suggestions, predictions, or inferences about interests.
 */
function buildInsights(
  destinations: readonly CompassDestination[],
  bytesDown: number,
  windowHours: number,
  feedback: InsightFeedback,
  hasPastDays: boolean,
  now: Date,
): CompassInsight[] {
  const insights: CompassInsight[] = [];
  const chosen = destinations.filter((entry) => entry.trafficClass !== "infrastructure");
  const named = chosen.filter((entry) => !entry.key.startsWith("ip:"));

  // Every site looks new on the first day of collection, so novelty is only
  // claimed once the daily history actually remembers an earlier day.
  if (hasPastDays) {
    for (const entry of named.filter((item) => item.knownDays === 1).slice(0, 2)) {
      if (entry.bytesUp + entry.bytesDown < 4_096) continue;
      insights.push({
        id: `new-destination:${entry.key}`,
        kind: "new-destination",
        title: `First time: ${entry.label}`,
        detail: `Nothing on this machine had contacted ${entry.label} before today. It exchanged ${formatBytes(entry.bytesUp + entry.bytesDown)} over ${entry.flows} connections.`,
        domain: entry.label,
        tone: "watch",
      });
    }
  }

  const top = chosen[0];
  if (top && bytesDown > 0 && top.bytesDown / bytesDown >= 0.25) {
    insights.push({
      id: `top-talker:${top.key}`,
      kind: "top-talker",
      title: `${top.label} used ${Math.round((top.bytesDown / bytesDown) * 100)}% of your download`,
      detail: `${formatBytes(top.bytesDown)} of the ${formatBytes(bytesDown)} you downloaded in ${windowLabel(windowHours)} came from ${top.label}.`,
      domain: null,
      tone: "neutral",
    });
  }

  const chatter = named.find(
    (entry) => entry.flows >= 40 && (entry.bytesUp + entry.bytesDown) / entry.flows < 2_048,
  );
  if (chatter) {
    const average = Math.round((chatter.bytesUp + chatter.bytesDown) / chatter.flows);
    insights.push({
      id: `background-chatter:${chatter.key}`,
      kind: "background-chatter",
      title: `${chatter.label} reconnects constantly`,
      detail: `${chatter.flows} tiny connections averaging ${formatBytes(average)} each. That is an app checking in, not you browsing. Mute it to clear the noise.`,
      domain: chatter.label,
      tone: "neutral",
    });
  }

  const plaintext = named
    .filter((entry) => entry.plaintextFlows > 0)
    .sort((a, b) => b.plaintextFlows - a.plaintextFlows);
  const plaintextFlows = plaintext.reduce((total, entry) => total + entry.plaintextFlows, 0);
  if (plaintext.length > 0) {
    const names = plaintext.slice(0, 3).map((entry) => entry.label);
    insights.push({
      id: `unencrypted:${plaintext[0]!.key}`,
      kind: "unencrypted",
      title: `${plaintextFlows} connections were not encrypted`,
      detail: `Traffic to ${names.join(", ")}${plaintext.length > names.length ? " and others" : ""} used plain HTTP, which anyone between you and the site can read. Often a captive-portal or update check rather than browsing.`,
      domain: null,
      tone: "watch",
    });
  }

  const uploader = named.find(
    (entry) => entry.bytesUp > entry.bytesDown * 2 && entry.bytesUp > 5_242_880,
  );
  if (uploader) {
    insights.push({
      id: `unusual-upload:${uploader.key}`,
      kind: "unusual-upload",
      title: `You sent ${formatBytes(uploader.bytesUp)} to ${uploader.label}`,
      detail: `That is more than twice what came back (${formatBytes(uploader.bytesDown)}). Normal for backups, file sync and video calls; worth a look otherwise.`,
      domain: null,
      tone: "watch",
    });
  }

  return insights
    .filter((insight) => {
      const saved = feedback[insight.id];
      if (!saved) return true;
      if (saved.status === "dismissed") return false;
      return !saved.snoozedUntil || new Date(saved.snoozedUntil) <= now;
    })
    .slice(0, 4);
}

export function buildCompassSummary(
  flows: Iterable<NetworkFlow>,
  config: CompassConfig,
  history: DomainHistory = {},
  feedback: InsightFeedback = {},
  now = new Date(),
): CompassSummary {
  let retainedFlows = 0;
  const directionCounts: Record<FlowDirection, number> = {
    outbound: 0,
    inbound: 0,
    internal: 0,
    unknown: 0,
  };
  let bytesUp = 0;
  let bytesDown = 0;
  let namedFlows = 0;
  let unnamedFlows = 0;
  let backgroundFlows = 0;
  let backgroundBytes = 0;
  let attributedFlows = 0;
  let earliestFlowAt: string | null = null;

  type Group = CompassDestination & {
    hostSet: Set<string>;
    processMap: Map<string, CompassDestination["processes"][number]>;
  };
  const groups = new Map<string, Group>();
  const categoryMap = new Map<string, CompassCategory & { dayKeys: Set<string> }>();

  for (const flow of flows) {
    retainedFlows += 1;
    if (flow.processName) attributedFlows += 1;
    directionCounts[flow.direction] += 1;
    if (!earliestFlowAt || flow.startedAt < earliestFlowAt) earliestFlowAt = flow.startedAt;
    // Headline totals answer "what did my apps move". Tunnel transport would
    // double-count every byte and resolver chatter would pad it, so both are
    // reported separately rather than folded in.
    if (flow.trafficClass === "infrastructure") {
      backgroundFlows += 1;
      backgroundBytes += flow.bytesUp + flow.bytesDown;
    } else {
      bytesUp += flow.bytesUp;
      bytesDown += flow.bytesDown;
    }
    if (flow.domain) namedFlows += 1;
    else if (flow.trafficClass !== "infrastructure") unnamedFlows += 1;

    const key = flow.domain ?? `ip:${flow.remoteIp}`;
    let group = groups.get(key);
    if (!group) {
      group = {
        key,
        label: flow.domain ?? flow.organization ?? flow.remoteIp,
        hostnames: [],
        hostSet: new Set<string>(),
        category: flow.category,
        categoryLabel: categoryLabel(flow.category),
        country: flow.country,
        asn: flow.asn,
        organization: flow.organization,
        trafficClass: flow.trafficClass,
        confidence: flow.domainConfidence,
        flows: 0,
        plaintextFlows: 0,
        bytesUp: 0,
        bytesDown: 0,
        firstSeen: flow.startedAt,
        lastSeen: flow.endedAt,
        knownDays: 1,
        firstSeenDay: null,
        processes: [],
        processMap: new Map(),
      };
      groups.set(key, group);
    }
    group.flows += 1;
    const processKey = flow.processName ?? "";
    const process = group.processMap.get(processKey) ?? {
      name: flow.processName,
      flows: 0,
      bytesUp: 0,
      bytesDown: 0,
    };
    process.flows += 1;
    process.bytesUp += flow.bytesUp;
    process.bytesDown += flow.bytesDown;
    group.processMap.set(processKey, process);
    if (flow.appProto === "http" || flow.remotePort === 80) group.plaintextFlows += 1;
    group.bytesUp += flow.bytesUp;
    group.bytesDown += flow.bytesDown;
    if (flow.startedAt < group.firstSeen) group.firstSeen = flow.startedAt;
    if (flow.endedAt > group.lastSeen) group.lastSeen = flow.endedAt;
    if (flow.hostname && group.hostSet.size < 8) group.hostSet.add(flow.hostname);
    group.country ??= flow.country;
    group.asn ??= flow.asn;
    group.organization ??= flow.organization;
    // An asserted name on any flow beats an inferred one on another.
    if (group.confidence !== "asserted" && flow.domainConfidence !== "unknown") {
      group.confidence = flow.domainConfidence;
    }
    if (group.trafficClass === "infrastructure" && flow.trafficClass !== "infrastructure") {
      group.trafficClass = flow.trafficClass;
    }

    if (!flow.category || flow.trafficClass === "infrastructure") continue;
    let category = categoryMap.get(flow.category);
    if (!category) {
      category = {
        id: flow.category,
        label: categoryLabel(flow.category) ?? flow.category,
        flows: 0,
        activeDays: 0,
        bytesUp: 0,
        bytesDown: 0,
        dayKeys: new Set<string>(),
      };
      categoryMap.set(flow.category, category);
    }
    category.flows += 1;
    category.bytesUp += flow.bytesUp;
    category.bytesDown += flow.bytesDown;
    category.dayKeys.add(flow.startedAt.slice(0, 10));
  }

  const destinations: CompassDestination[] = [];
  for (const group of groups.values()) {
    const { hostSet, processMap, ...rest } = group;
    const past = history[group.key];
    destinations.push({
      ...rest,
      hostnames: [...hostSet].sort(),
      knownDays: past?.days ?? 1,
      firstSeenDay: past?.firstDay ?? null,
      processes: [...processMap.values()].sort(
        (left, right) => right.bytesUp + right.bytesDown - (left.bytesUp + left.bytesDown),
      ),
    });
  }
  destinations.sort((a, b) => b.bytesDown + b.bytesUp - (a.bytesDown + a.bytesUp));

  const categories: CompassCategory[] = [...categoryMap.values()]
    .map(({ dayKeys, ...rest }) => ({ ...rest, activeDays: dayKeys.size }))
    .sort((a, b) => b.bytesDown + b.bytesUp - (a.bytesDown + a.bytesUp));

  return {
    enabled: config.enabled,
    paused: config.paused,
    insightsEnabled: config.insightsEnabled,
    windowHours: config.windowHours,
    retainedFlows,
    earliestFlowAt,
    bytesUp,
    bytesDown,
    directionCounts,
    destinations,
    categories,
    insights: config.insightsEnabled
      ? buildInsights(
          destinations,
          bytesDown,
          config.windowHours,
          feedback,
          Object.values(history).some((entry) => entry.days > 1),
          now,
        )
      : [],
    namedFlows,
    unnamedFlows,
    backgroundFlows,
    backgroundBytes,
    attributedFlows,
    unattributedFlows: retainedFlows - attributedFlows,
    attributionCoverage: retainedFlows === 0 ? 0 : attributedFlows / retainedFlows,
  };
}
