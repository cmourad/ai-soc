import { randomUUID } from "node:crypto";
import type { Protocol, SecurityEvent, Severity } from "@aisoc/shared";
import { clean, tailJsonl } from "./tail.js";

type EveAlert = {
  timestamp?: string;
  src_ip?: string;
  src_port?: number;
  dest_ip?: string;
  dest_port?: number;
  proto?: string;
  app_proto?: string;
  event_type?: string;
  direction?: string;
  alert?: {
    signature?: string;
    signature_id?: number;
    category?: string;
    severity?: number;
    metadata?: Record<string, string[]>;
  };
  tls?: { sni?: string };
  http?: { hostname?: string; url?: string; http_user_agent?: string };
  dns?: { rrname?: string };
  flow?: {
    bytes_toserver?: number;
    bytes_toclient?: number;
    pkts_toserver?: number;
    pkts_toclient?: number;
    src_ip?: string;
  };
};

function toProtocol(proto: string | undefined): Protocol {
  if (proto === "UDP" || proto === "ICMP") return proto;
  return "TCP";
}

export function eveToEvent(raw: EveAlert): SecurityEvent | null {
  if (raw.event_type !== "alert" || !raw.alert) return null;
  const severity = Math.min(4, Math.max(1, raw.alert.severity ?? 3)) as Severity;
  const tags = Object.values(raw.alert.metadata ?? {})
    .flat()
    .map((t) => clean(t, 40))
    .filter((t): t is string => Boolean(t))
    .slice(0, 12);

  return {
    id: randomUUID(),
    ts: raw.timestamp ?? new Date().toISOString(),
    srcIp: clean(raw.src_ip, 45) ?? "0.0.0.0",
    srcPort: raw.src_port ?? 0,
    destIp: clean(raw.dest_ip, 45) ?? "0.0.0.0",
    destPort: raw.dest_port ?? 0,
    proto: toProtocol(raw.proto),
    appProto: clean(raw.app_proto, 20),
    signature: clean(raw.alert.signature, 300) ?? "unknown signature",
    signatureId: raw.alert.signature_id ?? 0,
    category: clean(raw.alert.category, 100) ?? "Unknown",
    severity,
    tags,
    direction: raw.direction === "to_client" ? "to_client" : "to_server",
    sni: clean(raw.tls?.sni, 253),
    hostname: clean(raw.http?.hostname ?? raw.dns?.rrname, 253),
    url: clean(raw.http?.url, 400),
    userAgent: clean(raw.http?.http_user_agent, 300),
    bytesToServer: raw.flow?.bytes_toserver ?? 0,
    bytesToClient: raw.flow?.bytes_toclient ?? 0,
    pktsToServer: raw.flow?.pkts_toserver,
    pktsToClient: raw.flow?.pkts_toclient,
    flowInitiatorIp: clean(raw.flow?.src_ip, 45),
    source: "eve",
  };
}

/**
 * Tails eve.json from the current end of file, following truncation on
 * Suricata's log rotation.
 */
export function startEveSource(
  path: () => string,
  paused: () => boolean,
  emit: (event: SecurityEvent) => void,
  onError: (message: string) => void,
  observeRecord?: (record: unknown) => void,
): () => void {
  return tailJsonl({
    path,
    paused,
    onError,
    label: "eve.json",
    onRecord: (raw) => {
      observeRecord?.(raw);
      const event = eveToEvent(raw as EveAlert);
      if (event) emit(event);
    },
  });
}
