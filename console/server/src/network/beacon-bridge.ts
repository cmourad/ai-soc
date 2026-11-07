import { randomUUID } from "node:crypto";
import type { Protocol, SecurityEvent } from "@aisoc/shared";
import { getSettings } from "../settings.js";
import { listAlerts } from "../store.js";
import { ingestCompassDetection } from "../triage/pipeline.js";
import { type CompassBeaconFinding, scoreCompassBeacons } from "./beacon.js";
import { compassDomainHistory, listNetworkFlows } from "./state.js";

const SCAN_INTERVAL_MS = 30_000;
const REPEAT_HOLD_MS = 24 * 3_600_000;

let timer: NodeJS.Timeout | null = null;
let lastScan = 0;

function protocol(value: string): Protocol {
  const normalized = value.toUpperCase();
  if (normalized === "UDP" || normalized === "ICMP") return normalized;
  return "TCP";
}

export function beaconEvent(finding: CompassBeaconFinding, now = new Date()): SecurityEvent {
  return {
    id: randomUUID(),
    ts: now.toISOString(),
    srcIp: finding.localIp,
    srcPort: 0,
    destIp: finding.remoteIp,
    destPort: finding.remotePort,
    proto: protocol(finding.proto),
    appProto: finding.appProto ?? undefined,
    signature: `Compass detected repeated callbacks to ${finding.destination}`,
    signatureId: 9_100_001,
    category: "Potential Command and Control",
    severity: 2,
    tags: ["compass-beacon", "derived-aggregate", "no-auto-response"],
    direction: "to_client",
    bytesToServer: finding.medianBytesUp * finding.samples,
    bytesToClient: finding.medianBytesDown * finding.samples,
    source: "eve",
    processName: finding.processName ?? undefined,
    scenario: finding.key,
  };
}

function alreadyAlerted(key: string, now: number): boolean {
  return listAlerts().some(
    (alert) =>
      alert.origin === "compass_beacon" &&
      alert.event.scenario === key &&
      now - Date.parse(alert.createdAt) < REPEAT_HOLD_MS,
  );
}

export function scanCompassBeacons(now = new Date()): CompassBeaconFinding[] {
  lastScan = now.getTime();
  const settings = getSettings();
  if (
    !settings.networkCompass.enabled ||
    settings.networkCompass.paused ||
    !settings.networkCompass.beaconDetectionEnabled ||
    !settings.detection.enabled ||
    !settings.detection.heuristicsEnabled
  ) {
    return [];
  }

  const history = compassDomainHistory();
  const today = now.toISOString().slice(0, 10);
  const knownDays = Object.fromEntries(
    Object.entries(history).map(([destination, value]) => [destination, value.days]),
  );
  const hasPastDays = Object.values(history).some((value) => value.firstDay < today);
  const findings = scoreCompassBeacons(
    listNetworkFlows(),
    { hasPastDays, knownDays },
    settings.networkCompass.beaconSuppressions,
  );

  for (const finding of findings) {
    if (
      finding.detection.score < settings.detection.alertAtScore ||
      alreadyAlerted(finding.key, now.getTime())
    ) {
      continue;
    }
    ingestCompassDetection(beaconEvent(finding, now), finding.detection);
  }
  return findings;
}

export function scheduleCompassBeaconScan(now = Date.now()): void {
  if (timer) return;
  const delay = Math.max(0, SCAN_INTERVAL_MS - (now - lastScan));
  timer = setTimeout(() => {
    timer = null;
    scanCompassBeacons();
  }, delay);
}
