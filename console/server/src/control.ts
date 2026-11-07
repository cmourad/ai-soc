import { chmodSync, mkdirSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join } from "node:path";
import type { Incident, IncidentStatus, SensorHealth, Severity } from "@aisoc/shared";
import { assignIncident, setIncidentStatus } from "./incidents/correlate.js";
import { dnsSummary } from "./network/dns.js";
import { DATA_DIR } from "./paths.js";
import { computeStats } from "./projection.js";
import {
  applyResolverRoute,
  getPiholeStatus,
  getResolverStatus,
  type PiholeStatus,
  restartPihole,
  restartSensorServices,
  type SensorService,
} from "./sensor-control.js";
import { addAudit, listAudit, listIncidents } from "./store.js";

const SOCKET = process.env.AISOC_CONSOLE_CONTROL_SOCKET ?? join(DATA_DIR, "control.sock");
const MAX_REQUEST = 64 * 1024;
const ACTOR = "terminal:aisocctl";
const STATUSES = new Set<IncidentStatus>(["open", "investigating", "contained", "closed"]);

export type IncidentFilter = {
  status?: IncidentStatus | "active";
  severities?: Severity[];
  olderThanMs?: number;
  refs?: string[];
};

type ControlRequest =
  | { command: "status" }
  | { command: "sensors.status" }
  | { command: "sensors.restart"; downOnly?: boolean; confirm?: boolean }
  | { command: "pihole.status" }
  | { command: "pihole.restart"; confirm?: boolean }
  | { command: "dns.summary" }
  | { command: "dns.resolver"; apply?: boolean; confirm?: boolean }
  | { command: "audit.list"; limit?: number }
  | { command: "incidents.list"; filter?: IncidentFilter }
  | {
      command: "incidents.assign";
      filter?: IncidentFilter;
      assignee?: string;
      confirm?: boolean;
    }
  | { command: "incidents.close"; filter?: IncidentFilter; confirm?: boolean };

type IncidentSummary = Pick<
  Incident,
  "id" | "ref" | "status" | "severity" | "score" | "title" | "assignee" | "createdAt"
>;

function summary(incident: Incident): IncidentSummary {
  return {
    id: incident.id,
    ref: incident.ref,
    status: incident.status,
    severity: incident.severity,
    score: incident.score,
    title: incident.title,
    assignee: incident.assignee,
    createdAt: incident.createdAt,
  };
}

export function matchesIncidentFilter(
  incident: Incident,
  filter: IncidentFilter,
  now = Date.now(),
): boolean {
  if (filter.status === "active" && incident.status === "closed") return false;
  if (filter.status && filter.status !== "active" && incident.status !== filter.status)
    return false;
  if (filter.severities?.length && !filter.severities.includes(incident.severity)) return false;
  if (filter.olderThanMs && Date.parse(incident.createdAt) > now - filter.olderThanMs) return false;
  if (filter.refs?.length && !filter.refs.includes(incident.ref)) return false;
  return true;
}

function validFilter(value: unknown): value is IncidentFilter {
  if (!value || typeof value !== "object" || Array.isArray(value)) return value === undefined;
  const filter = value as Record<string, unknown>;
  if (
    filter.status !== undefined &&
    filter.status !== "active" &&
    !STATUSES.has(filter.status as IncidentStatus)
  ) {
    return false;
  }
  if (
    filter.severities !== undefined &&
    (!Array.isArray(filter.severities) ||
      filter.severities.some((severity) => ![1, 2, 3, 4].includes(severity as number)))
  ) {
    return false;
  }
  if (
    filter.olderThanMs !== undefined &&
    (typeof filter.olderThanMs !== "number" ||
      !Number.isFinite(filter.olderThanMs) ||
      filter.olderThanMs <= 0)
  ) {
    return false;
  }
  return !(
    filter.refs !== undefined &&
    (!Array.isArray(filter.refs) ||
      filter.refs.length > 500 ||
      filter.refs.some((ref) => typeof ref !== "string" || !/^INC-\d+$/.test(ref)))
  );
}

function selectedIncidents(filter: IncidentFilter = { status: "active" }): Incident[] {
  return listIncidents()
    .filter((incident) => matchesIncidentFilter(incident, filter))
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

function serviceForSensor(sensor: SensorHealth): SensorService {
  return sensor.path.includes("logs-vpn") ? "suricata-vpn" : "suricata";
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function sensorWroteAfter(sensor: SensorHealth | undefined, restartedAt: number): boolean {
  return (
    sensor?.ok === true &&
    sensor.lastWriteAt !== null &&
    Date.parse(sensor.lastWriteAt) >= restartedAt
  );
}

async function waitForSensorWrites(
  services: SensorService[],
  restartedAt: number,
  timeoutMs = 90_000,
): Promise<SensorHealth[]> {
  const deadline = Date.now() + timeoutMs;
  let sensors = computeStats().sensors;
  while (Date.now() < deadline) {
    const current = new Map(sensors.map((sensor) => [serviceForSensor(sensor), sensor]));
    if (services.every((service) => sensorWroteAfter(current.get(service), restartedAt))) {
      return sensors;
    }
    await sleep(2_000);
    sensors = computeStats().sensors;
  }
  return sensors;
}

/**
 * The Kubernetes deployment reports `starting` while its replacement pod is
 * becoming Ready. Reporting that transient state as the outcome of
 * a restart reads as a failure, so settle first.
 */
async function waitForPihole(timeoutMs = 90_000): Promise<PiholeStatus | undefined> {
  const deadline = Date.now() + timeoutMs;
  let result = await getPiholeStatus();
  while (Date.now() < deadline) {
    if (!result.pihole?.running || result.pihole.health !== "starting") return result.pihole;
    await sleep(3_000);
    result = await getPiholeStatus();
  }
  return result.pihole;
}

function piholeMessage(pihole: PiholeStatus | undefined): string {
  if (!pihole?.running) return "Pi-hole restarted, but its Kubernetes pod is not Ready.";
  if (pihole.health === "unhealthy") return "Pi-hole is running but reports unhealthy.";
  if (pihole.health === "starting") return "Pi-hole pod is still becoming Ready.";
  return "Pi-hole is running.";
}

export async function executeControlCommand(input: unknown): Promise<Record<string, unknown>> {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { ok: false, error: "request must be an object" };
  }
  const request = input as Partial<ControlRequest> & Record<string, unknown>;

  if (request.command === "sensors.status") {
    return { ok: true, sensors: computeStats().sensors };
  }

  if (request.command === "sensors.restart") {
    const sensors = computeStats().sensors;
    const services: SensorService[] =
      request.downOnly === false
        ? ["suricata", "suricata-vpn"]
        : [...new Set(sensors.filter((sensor) => !sensor.ok).map(serviceForSensor))];
    if (request.confirm !== true) {
      return {
        ok: true,
        dryRun: true,
        services,
        sensors,
        message: services.length
          ? `Would restart ${services.join(", ")}. Re-run with --confirm.`
          : "No down sensors matched.",
      };
    }
    if (services.length === 0)
      return { ok: true, changed: 0, services, message: "No sensors matched." };
    const restartedAt = Date.now();
    const result = await restartSensorServices(services);
    if (!result.ok) return { ok: false, error: result.error ?? "sensor restart failed" };
    for (const service of services) {
      addAudit(ACTOR, "sensor.restart", service, "Restarted from aisocctl.");
    }
    const updatedSensors = await waitForSensorWrites(services, restartedAt);
    const current = new Map(updatedSensors.map((sensor) => [serviceForSensor(sensor), sensor]));
    const ready = services.every((service) => sensorWroteAfter(current.get(service), restartedAt));
    return {
      ok: true,
      changed: services.length,
      services,
      sensors: updatedSensors,
      ready,
      output: result.output ?? "Restarted.",
      message: ready
        ? "All restarted sensors are writing EVE events."
        : "Containers restarted, but one or more sensors did not write EVE events within 90 seconds. Check Docker logs and interface availability.",
    };
  }

  if (request.command === "status") {
    const stats = computeStats();
    // Best effort: the helper being down must not hide the rest of the picture.
    const pihole = await getPiholeStatus();
    return { ok: true, stats, sensors: stats.sensors, pihole: pihole.pihole };
  }

  if (request.command === "pihole.status") {
    const result = await getPiholeStatus();
    return result.ok && result.pihole
      ? { ok: true, pihole: result.pihole }
      : { ok: false, error: result.error ?? "Pi-hole status failed" };
  }

  if (request.command === "pihole.restart") {
    if (request.confirm !== true) {
      return {
        ok: true,
        dryRun: true,
        message: "Would restart pihole. Re-run with --confirm.",
      };
    }
    const result = await restartPihole();
    if (!result.ok) return { ok: false, error: result.error ?? "Pi-hole restart failed" };
    addAudit(ACTOR, "pihole.restart", "pihole", "Restarted from aisocctl.");
    const pihole = await waitForPihole();
    return {
      ok: true,
      changed: 1,
      pihole,
      output: result.output ?? "Pi-hole restarted.",
      message: piholeMessage(pihole),
    };
  }

  if (request.command === "dns.summary") {
    return { ok: true, dns: await dnsSummary() };
  }

  if (request.command === "dns.resolver") {
    if (request.apply !== true) {
      const result = await getResolverStatus();
      return result.ok && result.resolver
        ? { ok: true, resolver: result.resolver }
        : { ok: false, error: result.error ?? "resolver status failed" };
    }
    if (request.confirm !== true) {
      const preview = await getResolverStatus();
      return {
        ok: true,
        dryRun: true,
        resolver: preview.resolver,
        message: "Would point the default DNS route at Pi-hole. Re-run with --confirm.",
      };
    }
    const applied = await applyResolverRoute();
    if (!applied.ok) return { ok: false, error: applied.error ?? "resolver apply failed" };
    addAudit(ACTOR, "dns.resolver_apply", "systemd-resolved", "Routed default DNS to Pi-hole.");
    const result = await getResolverStatus();
    return {
      ok: true,
      changed: 1,
      resolver: result.resolver,
      output: applied.output,
      message: result.resolver?.routed
        ? "Default DNS route is Pi-hole."
        : "Applied, but the route did not take. Check that Pi-hole is running and the VPN is not reinstalling its resolver.",
    };
  }

  if (request.command === "audit.list") {
    const requested = typeof request.limit === "number" ? request.limit : 20;
    const limit = Math.min(500, Math.max(1, Math.floor(requested)));
    const entries = listAudit().slice(-limit).reverse();
    return { ok: true, matched: entries.length, audit: entries };
  }

  if (
    request.command !== "incidents.list" &&
    request.command !== "incidents.assign" &&
    request.command !== "incidents.close"
  ) {
    return { ok: false, error: "unknown command" };
  }
  if (!validFilter(request.filter)) return { ok: false, error: "invalid incident filter" };
  const filter = request.filter ?? { status: "active" };
  const incidents = selectedIncidents(filter);

  if (request.command === "incidents.list") {
    return { ok: true, matched: incidents.length, incidents: incidents.slice(0, 500).map(summary) };
  }

  if (request.confirm !== true) {
    return {
      ok: true,
      dryRun: true,
      matched: incidents.length,
      incidents: incidents.slice(0, 500).map(summary),
      message: `Preview only. Re-run with --confirm to ${request.command === "incidents.close" ? "close" : "assign"} these incidents.`,
    };
  }

  if (request.command === "incidents.assign") {
    const assignee =
      typeof request.assignee === "string" ? request.assignee.trim().slice(0, 100) : "";
    if (!assignee) return { ok: false, error: "a non-empty assignee is required" };
    for (const incident of incidents) assignIncident(incident.id, assignee, ACTOR);
    addAudit(
      ACTOR,
      "incident.bulk_assign",
      `${incidents.length} incidents`,
      `Assigned to ${assignee}.`,
    );
    return { ok: true, changed: incidents.length, assignee, incidents: incidents.map(summary) };
  }

  for (const incident of incidents) setIncidentStatus(incident.id, "closed", ACTOR);
  addAudit(ACTOR, "incident.bulk_close", `${incidents.length} incidents`, "Closed from aisocctl.");
  return { ok: true, changed: incidents.length, incidents: incidents.map(summary) };
}

export async function startConsoleControlServer(): Promise<void> {
  mkdirSync(dirname(SOCKET), { recursive: true, mode: 0o700 });
  rmSync(SOCKET, { force: true });
  const server = createServer((socket) => {
    socket.setEncoding("utf8");
    let buffer = "";
    let handled = false;
    socket.on("data", (chunk) => {
      if (handled) return;
      buffer += chunk;
      if (buffer.length > MAX_REQUEST) {
        handled = true;
        socket.end(`${JSON.stringify({ ok: false, error: "request too large" })}\n`);
        return;
      }
      const newline = buffer.indexOf("\n");
      if (newline === -1) return;
      handled = true;
      let request: unknown;
      try {
        request = JSON.parse(buffer.slice(0, newline));
      } catch {
        socket.end(`${JSON.stringify({ ok: false, error: "invalid JSON" })}\n`);
        return;
      }
      void executeControlCommand(request)
        .then((response) => socket.end(`${JSON.stringify(response)}\n`))
        .catch((error: unknown) =>
          socket.end(
            `${JSON.stringify({ ok: false, error: error instanceof Error ? error.message : "control failed" })}\n`,
          ),
        );
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(SOCKET, () => {
      server.off("error", reject);
      chmodSync(SOCKET, 0o600);
      resolve();
    });
  });
}
