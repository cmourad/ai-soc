import { networkInterfaces } from "node:os";
import { isAbsolute } from "node:path";
import type { SecurityEvent } from "@aisoc/shared";
import { setLocalNetworks } from "@aisoc/shared";
import { broadcast } from "./bus.js";
import { scheduleCompassBeaconScan } from "./network/beacon-bridge.js";
import { EveFlowCorrelator } from "./network/compass.js";
import { addNetworkFlow } from "./network/state.js";
import { REPO_ROOT } from "./paths.js";
import { agentProcessName } from "./response/agent.js";
import { getSettings } from "./settings.js";
import { startClusterSource } from "./sources/cluster.js";
import { startEveSource } from "./sources/eve.js";
import { startSeedSource } from "./sources/seed.js";
import { clusterPaths, evePaths, readSensorHealth } from "./sources/sensor.js";
import { addEvent, addNotification, getVpn } from "./store.js";
import { ingestEvent } from "./triage/pipeline.js";
import { listServers } from "./vpn/servers.js";

/**
 * Everything between a sensor and the triage queue: which source is running,
 * whether its taps are alive, and the flow correlation that turns raw eve
 * records into Compass flows.
 *
 * It is a module rather than part of the entrypoint because the source can be
 * switched at runtime — `syncSource` is on a 1s timer and reconciles the
 * running source against settings — so this is a small state machine with a
 * lifecycle, not composition.
 */

const sensorsDown = new Set<string>();

export function pollSensors(): void {
  const { ingest, clusterTelemetry } = getSettings();
  if (ingest.paused) {
    sensorsDown.clear();
    return;
  }

  const watched = [
    ...(ingest.source === "eve" ? readSensorHealth(evePaths()) : []),
    ...readSensorHealth(clusterPaths(), Date.now(), clusterTelemetry.silenceMinutes * 60_000),
  ];
  for (const sensor of watched) {
    if (!sensor.ok && !sensorsDown.has(sensor.path)) {
      sensorsDown.add(sensor.path);
      addNotification({
        kind: "system",
        level: "warning",
        title: `Sensor ${sensor.label} stopped reporting`,
        body: `${sensor.detail}. Nothing is reaching detection or triage from this sensor until it is writing again.`,
        linkView: "traffic",
        linkId: null,
      });
    } else if (sensor.ok && sensorsDown.delete(sensor.path)) {
      addNotification({
        kind: "system",
        level: "info",
        title: `Sensor ${sensor.label} is back`,
        body: "Records are arriving again. Anything the sensor missed while it was down is not recoverable.",
        linkView: "traffic",
        linkId: null,
      });
    }
  }
}

function eveError(message: string): void {
  // Say where relative paths are anchored — the usual cause is a path written
  // relative to the console directory rather than the repository root.
  const configured = getSettings().ingest.evePath;
  const hint = isAbsolute(configured) ? "" : ` (relative paths resolve against ${REPO_ROOT})`;
  broadcast({ type: "toast", level: "error", message: `${message}${hint}` });
}

export function handleEvent(event: SecurityEvent): void {
  addEvent(event);
  ingestEvent(event);
}

const flowCorrelator = new EveFlowCorrelator();
let localNetworkAddresses: string[] = [];

export function refreshLocalNetworkAddresses(): void {
  try {
    localNetworkAddresses = Object.values(networkInterfaces())
      .flat()
      .filter((address): address is NonNullable<typeof address> => Boolean(address))
      .map((address) => address.address);
  } catch {
    // A restrictive service sandbox may deny the netlink query behind
    // os.networkInterfaces(). Configured home networks remain authoritative;
    // optional host discovery must never make the console unavailable.
    localNetworkAddresses = [];
  }
  publishLocalNetworks();
}

/**
 * The detection path asks "is this address ours" without a settings handle, so
 * the answer is pushed to it whenever either input changes.
 */
export function publishLocalNetworks(): void {
  setLocalNetworks(getSettings().site.homeNetworks, localNetworkAddresses);
}

refreshLocalNetworkAddresses();

async function attributeAndAddNetworkFlow(
  flow: NonNullable<ReturnType<EveFlowCorrelator["consume"]>>,
) {
  const compass = getSettings().networkCompass;
  if (!compass.enabled || compass.paused) return;
  const processName = await agentProcessName(flow).catch(() => null);
  addNetworkFlow({ ...flow, processName });
  scheduleCompassBeaconScan();
}

function handleEveRecord(raw: unknown): void {
  if (!raw || typeof raw !== "object") return;
  const record = raw as { iface?: unknown; in_iface?: unknown };
  const sensor =
    typeof record.iface === "string"
      ? record.iface.slice(0, 32)
      : typeof record.in_iface === "string"
        ? record.in_iface.slice(0, 32)
        : "suricata";
  const flow = flowCorrelator.consume(
    raw,
    sensor,
    getSettings().site.homeNetworks,
    localNetworkAddresses,
    tunnelEndpoints(),
  );
  if (flow) void attributeAndAddNetworkFlow(flow);
}

/**
 * Both the physical and tunnel EVE streams are tailed, so every byte inside the
 * VPN is also seen as an encrypted flow to the exit node. Naming that endpoint
 * lets Compass score it as transport instead of reporting a phantom site that
 * doubles the operator's traffic totals.
 */
export function tunnelEndpoints(): string[] {
  const vpn = getVpn();
  const endpoints = [vpn.exitIp].filter((value): value is string => Boolean(value));
  const server = vpn.serverId
    ? listServers(getSettings().site).find((entry) => entry.id === vpn.serverId)
    : null;
  if (server) endpoints.push(server.host);
  return endpoints;
}

// Source lifecycle: restart the reader whenever the configured source changes.
let stopSource: (() => void) | null = null;
let activeSource: string | null = null;
let stopCluster: (() => void) | null = null;
let activeCluster: string | null = null;

/**
 * The cluster streams run beside the network sensor rather than instead of it.
 * They are reconciled separately so that switching ingest to `seed` for a demo,
 * or a dead eve.json, never silently stops cluster coverage.
 */
export function syncClusterSource(): void {
  const { enabled, spoolPath } = getSettings().clusterTelemetry;
  const desired = enabled ? spoolPath : "";
  if (desired === activeCluster) return;
  activeCluster = desired;
  stopCluster?.();
  stopCluster = null;
  if (!desired) return;
  const [path] = clusterPaths();
  if (!path) return;
  stopCluster = startClusterSource(
    () => path,
    () => getSettings().ingest.paused,
    handleEvent,
    (message) => broadcast({ type: "toast", level: "error", message }),
  );
}

export function syncSource(): void {
  const source = getSettings().ingest.source;
  const desired = `${source}:${getSettings().ingest.evePath}`;
  if (desired === activeSource) return;
  stopSource?.();
  activeSource = desired;
  if (source === "seed") {
    stopSource = startSeedSource(
      () => getSettings().ingest.eventsPerSecond,
      () => getSettings().ingest.paused,
      handleEvent,
    );
  } else {
    const stops = evePaths().map((path) =>
      startEveSource(
        () => path,
        () => getSettings().ingest.paused,
        handleEvent,
        eveError,
        handleEveRecord,
      ),
    );
    stopSource = () => {
      for (const stop of stops) stop();
    };
  }
  broadcast({ type: "toast", level: "info", message: `Ingest source: ${source}` });
}
