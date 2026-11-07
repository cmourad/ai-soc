import { createConnection } from "node:net";

const SOCKET = process.env.AISOC_SENSOR_CONTROL_SOCKET ?? "/run/aisoc-sensor-control/control.sock";
const MAX_RESPONSE = 64 * 1024;

export type SensorService = "suricata" | "suricata-vpn";
export type PiholeStatus = {
  installed: boolean;
  running: boolean;
  state: string;
  health: string;
  status?: string;
};

export type ResolverStatus = {
  interface: string;
  dns: string[];
  domains: string[];
  expected: string | null;
  vpn: { interface: string; dns: string[]; domains: string[] };
  routed: boolean;
};

type ControlResponse = {
  ok: boolean;
  output?: string;
  error?: string;
  pihole?: PiholeStatus;
  resolver?: ResolverStatus;
};

function requestControl(payload: Record<string, unknown>): Promise<ControlResponse> {
  return new Promise((resolve) => {
    const socket = createConnection(SOCKET);
    let buffer = "";
    let settled = false;

    const finish = (result: ControlResponse) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };

    socket.setEncoding("utf8");
    socket.setTimeout(130_000, () => finish({ ok: false, error: "sensor control timed out" }));
    socket.on("connect", () => {
      socket.write(`${JSON.stringify(payload)}\n`);
    });
    socket.on("data", (chunk) => {
      buffer += chunk;
      if (buffer.length > MAX_RESPONSE) {
        finish({ ok: false, error: "sensor control response was too large" });
        return;
      }
      const newline = buffer.indexOf("\n");
      if (newline === -1) return;
      try {
        const response = JSON.parse(buffer.slice(0, newline)) as ControlResponse;
        finish(
          response.ok
            ? {
                ok: true,
                output: response.output,
                pihole: response.pihole,
                resolver: response.resolver,
              }
            : { ok: false, error: response.error ?? "sensor control failed" },
        );
      } catch {
        finish({ ok: false, error: "sensor control returned invalid JSON" });
      }
    });
    socket.on("error", (error) => finish({ ok: false, error: error.message }));
    socket.on("end", () => finish({ ok: false, error: "sensor control closed without a reply" }));
  });
}

export function restartSensorServices(services: SensorService[]): Promise<ControlResponse> {
  return requestControl({ action: "restart", services });
}

export function restartPihole(): Promise<ControlResponse> {
  return requestControl({ action: "restart", services: ["pihole"] });
}

export function getPiholeStatus(): Promise<ControlResponse> {
  return requestControl({ action: "status", service: "pihole" });
}

export function getResolverStatus(): Promise<ControlResponse> {
  return requestControl({ action: "resolver", mode: "status" });
}

export function applyResolverRoute(): Promise<ControlResponse> {
  return requestControl({ action: "resolver", mode: "apply" });
}
