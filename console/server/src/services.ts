import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);

export type ServiceKind = "systemd" | "docker";

export interface ServiceInfo {
  name: string;
  label: string;
  kind: ServiceKind;
  unit: string;
  active: boolean;
  command: string;
}

export interface ServiceGroup {
  title: string;
  services: ServiceInfo[];
}

const SYSTEMD_SERVICES: ServiceInfo[] = [
  {
    name: "aisoc-console",
    label: "aisoc-console",
    kind: "systemd",
    unit: "aisoc-console.service",
    active: false,
    command: "systemctl",
  },
  {
    name: "aisoc-agent",
    label: "aisoc-agent",
    kind: "systemd",
    unit: "aisoc-agent.service",
    active: false,
    command: "systemctl",
  },
  {
    name: "aisoc-host-events",
    label: "aisoc-host-events",
    kind: "systemd",
    unit: "aisoc-host-events.service",
    active: false,
    command: "systemctl",
  },
  {
    name: "aisoc-process-helper",
    label: "aisoc-process-helper",
    kind: "systemd",
    unit: "aisoc-process-helper.service",
    active: false,
    command: "systemctl",
  },
  {
    name: "aisoc-vpn-helper",
    label: "aisoc-vpn-helper",
    kind: "systemd",
    unit: "aisoc-vpn-helper.service",
    active: false,
    command: "systemctl",
  },
];

const SYSTEMD_TIMERS: ServiceInfo[] = [
  {
    name: "aisoc-digest",
    label: "aisoc-digest",
    kind: "systemd",
    unit: "aisoc-digest.timer",
    active: false,
    command: "systemctl",
  },
  {
    name: "aisoc-rules",
    label: "aisoc-rules",
    kind: "systemd",
    unit: "aisoc-rules.timer",
    active: false,
    command: "systemctl",
  },
  {
    name: "aisoc-watchdog",
    label: "aisoc-watchdog",
    kind: "systemd",
    unit: "aisoc-watchdog.timer",
    active: false,
    command: "systemctl",
  },
];

const DOCKER_SERVICES: ServiceInfo[] = [
  {
    name: "suricata",
    label: "Suricata (LAN)",
    kind: "docker",
    unit: "suricata",
    active: false,
    command: "docker compose",
  },
  {
    name: "suricata-vpn",
    label: "Suricata (VPN)",
    kind: "docker",
    unit: "suricata-vpn",
    active: false,
    command: "docker compose",
  },
];

export const SERVICE_GROUPS: ServiceGroup[] = [
  { title: "Docker", services: DOCKER_SERVICES },
  { title: "Systemd", services: SYSTEMD_SERVICES },
  { title: "Timers", services: SYSTEMD_TIMERS },
];

const COMPOSE_FILE = process.env.COMPOSE_FILE ?? "";

function sudo(...args: string[]): Promise<{ stdout: string; stderr: string }> {
  return exec("sudo", args);
}

async function checkSystemd(service: ServiceInfo): Promise<boolean> {
  try {
    const { stdout } = await sudo("systemctl", "is-active", service.unit);
    return stdout.trim() !== "inactive";
  } catch {
    return false;
  }
}

async function checkDocker(service: ServiceInfo): Promise<boolean> {
  try {
    const args = [
      "compose",
      ...(COMPOSE_FILE ? ["-f", COMPOSE_FILE] : []),
      "ps",
      service.unit,
      "--format",
      "json",
    ];
    const { stdout } = await exec("docker", args);
    return stdout.includes('"Running": true');
  } catch {
    return false;
  }
}

export async function getServiceStatus(): Promise<ServiceGroup[]> {
  const groups: ServiceGroup[] = [];

  for (const group of SERVICE_GROUPS) {
    const services = await Promise.all(
      group.services.map(async (s) => ({
        ...s,
        active: s.kind === "systemd" ? await checkSystemd(s) : await checkDocker(s),
      })),
    );
    groups.push({ title: group.title, services });
  }

  return groups;
}

export const SERVICE_ACTIONS = ["start", "stop", "restart", "logs"] as const;

export type ServiceAction = (typeof SERVICE_ACTIONS)[number];

export function isServiceAction(value: string): value is ServiceAction {
  return (SERVICE_ACTIONS as readonly string[]).includes(value);
}

export async function controlService(
  serviceName: string,
  action: ServiceAction,
): Promise<{ ok: boolean; output?: string; error?: string }> {
  const all = SERVICE_GROUPS.flatMap((g) => g.services);
  const service = all.find((s) => s.name === serviceName);
  if (!service) return { ok: false, error: `Unknown service: ${serviceName}` };

  try {
    let result: { stdout: string; stderr: string };

    if (service.kind === "systemd") {
      if (action === "logs") {
        result = await exec("sudo", [
          "journalctl",
          "-u",
          service.unit.replace(/\.timer$/, ".service").replace(/\.service$/, ""),
          "-n",
          "50",
          "--no-pager",
        ]);
      } else {
        result = await sudo("systemctl", action, service.unit);
      }
    } else {
      const composeArgs = ["compose", ...(COMPOSE_FILE ? ["-f", COMPOSE_FILE] : [])];
      if (action === "logs") {
        result = await exec("docker", [...composeArgs, "logs", "--tail=50", service.unit]);
      } else {
        result = await exec("docker", [
          ...composeArgs,
          action === "restart" ? "up" : action,
          "-d",
          service.unit,
        ]);
      }
    }

    return {
      ok: true,
      output: result.stdout || result.stderr || "Done.",
    };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : "Unknown error",
    };
  }
}
