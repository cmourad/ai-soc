import { randomUUID } from "node:crypto";
import type {
  Detection,
  DetectionHit,
  DomainConfidence,
  NetworkFlow,
  Severity,
} from "@aisoc/shared";
import { mitre } from "@aisoc/shared";
import { detectionFromHits } from "../detect/engine.js";

const MIN_SAMPLES = 10;
const MIN_SPAN_MS = 10 * 60_000;
const MIN_INTERVAL_MS = 5_000;
const MAX_INTERVAL_MS = 10 * 60_000;
const MAX_MEDIAN_BYTES = 16 * 1_024;
const HISTOGRAM_BASE = 1.25;

/**
 * STUN. A destination this host exchanges binding requests with is a relay
 * being measured for latency, and mesh VPNs measure every relay they know on a
 * fixed schedule — which is a beacon cadence by construction. Suricata reports
 * app_proto `failed` on these, so the port is the only handle.
 */
const NAT_TRAVERSAL_PORTS = new Set([3478, 3479, 5349, 5350]);

/**
 * Client UDP normally draws a fresh ephemeral port per flow. Many flows sharing
 * one pinned local port is a tunnel endpoint holding a socket open, which is
 * what separates a WireGuard peer from a callback target on the same address.
 */
const MIN_PINNED_DATAGRAMS = 5;

const EXPECTED_POLLERS = new Set([
  "chrome",
  "chromium",
  "chronyd",
  "code",
  "discord",
  "electron",
  "firefox",
  "firefox-bin",
  "grafana",
  "grafana-server",
  "networkmanager",
  "ntpd",
  "steam",
  "systemd-timesyn",
  "systemd-timesyncd",
  "tailscaled",
  "telegram",
  "telegram-desktop",
]);

export interface BeaconHistory {
  hasPastDays: boolean;
  knownDays: Readonly<Record<string, number>>;
}

export interface CompassBeaconFinding {
  key: string;
  destinationKey: string;
  destination: string;
  localIp: string;
  remoteIp: string;
  remotePort: number;
  proto: string;
  appProto: string | null;
  processName: string | null;
  firstSeen: string;
  lastSeen: string;
  samples: number;
  spanMs: number;
  intervalMs: number;
  intervalConcentration: number;
  medianBytes: number;
  medianBytesUp: number;
  medianBytesDown: number;
  payloadConcentration: number;
  encrypted: boolean;
  detection: Detection;
}

type Group = {
  destinationKey: string;
  destination: string;
  remoteIp: string;
  processName: string | null;
  confidence: DomainConfidence;
  flows: NetworkFlow[];
};

/**
 * What else this host does with an address, gathered before the beacon filters
 * narrow the set. A candidate group only ever holds one protocol's flows, so
 * without this the scorer cannot tell a lone HTTP callback apart from the probe
 * side of a mesh relay it is also tunnelling through.
 */
type PeerContext = {
  natTraversal: boolean;
  udpFlowsByLocalPort: Map<number, number>;
};

function peerContexts(flows: readonly NetworkFlow[]): Map<string, PeerContext> {
  const contexts = new Map<string, PeerContext>();
  for (const flow of flows) {
    let context = contexts.get(flow.remoteIp);
    if (!context) {
      context = { natTraversal: false, udpFlowsByLocalPort: new Map() };
      contexts.set(flow.remoteIp, context);
    }
    if (NAT_TRAVERSAL_PORTS.has(flow.remotePort)) context.natTraversal = true;
    if (flow.proto.toLowerCase() !== "udp") continue;
    const seen = context.udpFlowsByLocalPort.get(flow.localPort) ?? 0;
    context.udpFlowsByLocalPort.set(flow.localPort, seen + 1);
  }
  return contexts;
}

function isMeshRelay(context: PeerContext | undefined): boolean {
  if (!context) return false;
  if (context.natTraversal) return true;
  for (const count of context.udpFlowsByLocalPort.values()) {
    if (count >= MIN_PINNED_DATAGRAMS) return true;
  }
  return false;
}

function median(values: readonly number[]): number {
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[middle - 1]! + sorted[middle]!) / 2 : sorted[middle]!;
}

function intervalPeak(gaps: readonly number[]): { intervalMs: number; concentration: number } {
  const buckets = new Map<number, number>();
  for (const gap of gaps) {
    const bucket = Math.round(Math.log(gap) / Math.log(HISTOGRAM_BASE));
    buckets.set(bucket, (buckets.get(bucket) ?? 0) + 1);
  }
  let peak = 0;
  let peakCount = 0;
  for (const bucket of buckets.keys()) {
    const count =
      (buckets.get(bucket - 1) ?? 0) + (buckets.get(bucket) ?? 0) + (buckets.get(bucket + 1) ?? 0);
    if (count > peakCount) {
      peak = bucket;
      peakCount = count;
    }
  }
  const nearPeak = gaps.filter((gap) => {
    const bucket = Math.round(Math.log(gap) / Math.log(HISTOGRAM_BASE));
    return Math.abs(bucket - peak) <= 1;
  });
  return {
    intervalMs: Math.round(median(nearPeak.length > 0 ? nearPeak : gaps)),
    concentration: peakCount / gaps.length,
  };
}

function payloadShape(flows: readonly NetworkFlow[]): {
  medianBytes: number;
  medianBytesUp: number;
  medianBytesDown: number;
  concentration: number;
} {
  const sizes = flows.map((flow) => flow.bytesUp + flow.bytesDown);
  const typical = median(sizes);
  const tolerance = Math.max(256, typical * 0.35);
  return {
    medianBytes: Math.round(typical),
    medianBytesUp: Math.round(median(flows.map((flow) => flow.bytesUp))),
    medianBytesDown: Math.round(median(flows.map((flow) => flow.bytesDown))),
    concentration:
      sizes.filter((size) => Math.abs(size - typical) <= tolerance).length / sizes.length,
  };
}

function hit(input: {
  ruleId: string;
  name: string;
  description: string;
  score: number;
  confidence: number;
  field: string;
  value: string;
  severity?: Severity;
  mitre?: ReturnType<typeof mitre>;
}): DetectionHit {
  return {
    id: randomUUID(),
    kind: "heuristic",
    ruleId: input.ruleId,
    name: input.name,
    description: input.description,
    score: input.score,
    severity: input.severity ?? 2,
    field: input.field,
    value: input.value,
    origin: "aisoc compass behavioural analytics",
    confidence: input.confidence,
    mitre: input.mitre ?? [],
  };
}

function score(
  group: Group,
  history: BeaconHistory,
  peer: PeerContext | undefined,
): CompassBeaconFinding | null {
  if (isMeshRelay(peer)) return null;
  const flows = [...group.flows].sort(
    (left, right) => Date.parse(left.startedAt) - Date.parse(right.startedAt),
  );
  if (flows.length < MIN_SAMPLES || !history.hasPastDays) return null;

  const times = flows.map((flow) => Date.parse(flow.startedAt));
  if (times.some((time) => !Number.isFinite(time))) return null;
  const spanMs = times.at(-1)! - times[0]!;
  if (spanMs < MIN_SPAN_MS) return null;
  const gaps = times
    .slice(1)
    .map((time, index) => time - times[index]!)
    .filter((gap) => gap > 0);
  if (gaps.length < MIN_SAMPLES - 1) return null;

  const cadence = intervalPeak(gaps);
  if (
    cadence.intervalMs < MIN_INTERVAL_MS ||
    cadence.intervalMs > MAX_INTERVAL_MS ||
    cadence.concentration < 0.8
  ) {
    return null;
  }

  const payload = payloadShape(flows);
  if (payload.medianBytes > MAX_MEDIAN_BYTES || payload.concentration < 0.8) return null;

  const knownDays = history.knownDays[group.destinationKey] ?? 1;
  if (
    knownDays !== 1 ||
    group.confidence !== "unknown" ||
    !group.destinationKey.startsWith("ip:")
  ) {
    return null;
  }

  const normalizedProcess = group.processName?.trim().toLowerCase() ?? null;
  if (normalizedProcess && EXPECTED_POLLERS.has(normalizedProcess)) return null;

  const seconds = Math.round(cadence.intervalMs / 1_000);
  const hits: DetectionHit[] = [
    hit({
      ruleId: "AISOC-COMPASS-BEACON-CADENCE",
      name: "Repeated low-jitter callback cadence",
      description: `${flows.length} connections span ${Math.round(spanMs / 60_000)} minutes with ${(cadence.concentration * 100).toFixed(0)}% of intervals concentrated around ${seconds} seconds.`,
      score: 30,
      confidence: cadence.concentration,
      field: "flow.startedAt",
      value: `every ~${seconds}s`,
      mitre: mitre("T1071"),
    }),
    hit({
      ruleId: "AISOC-COMPASS-BEACON-UNRESOLVED",
      name: "Destination has no observed name",
      description: "TLS, HTTP and recent DNS correlation supplied no destination name.",
      score: 25,
      confidence: 0.9,
      field: "remoteIp",
      value: group.remoteIp,
    }),
    hit({
      ruleId: "AISOC-COMPASS-BEACON-NOVEL",
      name: "Destination is new to this ledger",
      description: "Longer-lived daily history has not seen this destination before today.",
      score: 22,
      confidence: 0.9,
      field: "destination_days",
      value: "knownDays=1",
    }),
    hit({
      ruleId: "AISOC-COMPASS-BEACON-PROCESS",
      name: group.processName
        ? "Unexpected process owns the callbacks"
        : "Callback process is unknown",
      description: group.processName
        ? `${group.processName} is not one of the workstation's expected background pollers.`
        : "No exact live socket owner was captured for these repeated callbacks.",
      score: group.processName ? 32 : 24,
      confidence: group.processName ? 0.95 : 0.8,
      field: "processName",
      value: group.processName ?? "unknown",
    }),
    hit({
      ruleId: "AISOC-COMPASS-BEACON-PAYLOAD",
      name: "Small uniform exchanges",
      description: `${(payload.concentration * 100).toFixed(0)}% of connections stay near a ${payload.medianBytes}-byte exchange.`,
      score: 18,
      confidence: payload.concentration * 0.85,
      field: "flow.bytes",
      value: `median=${payload.medianBytes}`,
    }),
  ];

  const encrypted =
    flows.filter((flow) => flow.appProto === "tls" || flow.appProto === "quic").length /
      flows.length >=
    0.8;
  if (encrypted) {
    hits.push(
      hit({
        ruleId: "AISOC-COMPASS-BEACON-ENCRYPTED",
        name: "Callbacks use an encrypted channel",
        description: "At least 80% of the repeated connections use TLS or QUIC.",
        score: 8,
        confidence: 0.8,
        field: "appProto",
        value: "tls/quic",
        mitre: mitre("T1573"),
      }),
    );
  }

  return {
    key: `${group.destinationKey}|process:${normalizedProcess ?? "unknown"}|sensor:${flows[0]!.sensor}`,
    destinationKey: group.destinationKey,
    destination: group.destination,
    localIp: flows[0]!.localIp,
    remoteIp: group.remoteIp,
    remotePort: flows[0]!.remotePort,
    proto: flows[0]!.proto,
    appProto: flows[0]!.appProto,
    processName: group.processName,
    firstSeen: flows[0]!.startedAt,
    lastSeen: flows.at(-1)!.startedAt,
    samples: flows.length,
    spanMs,
    intervalMs: cadence.intervalMs,
    intervalConcentration: cadence.concentration,
    medianBytes: payload.medianBytes,
    medianBytesUp: payload.medianBytesUp,
    medianBytesDown: payload.medianBytesDown,
    payloadConcentration: payload.concentration,
    encrypted,
    detection: detectionFromHits(hits),
  };
}

export function scoreCompassBeacons(
  flows: Iterable<NetworkFlow>,
  history: BeaconHistory,
  suppressions: readonly string[] = [],
): CompassBeaconFinding[] {
  const suppressed = new Set(suppressions);
  const groups = new Map<string, Group>();
  // Built from every flow, including the infrastructure and inbound ones the
  // candidate loop below discards.
  const allFlows = [...flows];
  const contexts = peerContexts(allFlows);

  for (const flow of allFlows) {
    if (
      flow.direction !== "outbound" ||
      flow.trafficClass === "infrastructure" ||
      flow.trafficClass === "local"
    ) {
      continue;
    }
    const destinationKey = flow.domain ?? `ip:${flow.remoteIp}`;
    if (suppressed.has(destinationKey)) continue;
    const processKey = flow.processName?.trim().toLowerCase() ?? "unknown";
    const key = `${flow.sensor}|${destinationKey}|${processKey}`;
    const group = groups.get(key) ?? {
      destinationKey,
      destination: flow.domain ?? flow.organization ?? flow.remoteIp,
      remoteIp: flow.remoteIp,
      processName: flow.processName,
      confidence: flow.domainConfidence,
      flows: [],
    };
    group.flows.push(flow);
    if (group.confidence !== "asserted" && flow.domainConfidence === "asserted") {
      group.confidence = "asserted";
    } else if (group.confidence === "unknown" && flow.domainConfidence === "inferred") {
      group.confidence = "inferred";
    }
    groups.set(key, group);
  }

  const findings: CompassBeaconFinding[] = [];
  for (const group of groups.values()) {
    const finding = score(group, history, contexts.get(group.remoteIp));
    if (finding) findings.push(finding);
  }
  return findings.sort((left, right) => right.detection.score - left.detection.score);
}
