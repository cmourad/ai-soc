import { createHash, randomUUID } from "node:crypto";
import type { KubernetesContext, SecurityEvent, Severity } from "@aisoc/shared";
import { clean, tailJsonl } from "./tail.js";

/**
 * Cluster telemetry: Tetragon's syscall stream and the k3s API-server audit
 * log, both arriving through the root collector's spool
 * (`scripts/cluster_tail.py`).
 *
 * The console never opens the source files. They are root-only for good reason
 * — one carries every process argument on this host, the other carries the
 * cluster's object metadata — and an unprivileged decision service should not
 * be the thing that holds that read. The collector minimises and the console
 * classifies, which is also why a regression in the audit policy cannot push
 * secret material into a prompt: the spool has no request bodies to leak.
 *
 * Events arrive at low severity by design. Volume is real (hundreds of execs a
 * second before filtering), so admission is the detection engine's job: a rule
 * hit raises the score above `detection.alertAtScore` and pulls the event into
 * triage, while everything else stays a recorded observation.
 */

export type ClusterStream = "tetragon" | "k3s-audit" | "collector";

type SpoolRecord = {
  _stream?: string;
  ts?: string;
  record?: Record<string, unknown>;
};

type TetragonProcess = {
  binary?: string;
  arguments?: string;
  pid?: number;
  uid?: number;
  auid?: number;
  cwd?: string;
  pod?: { namespace?: string; name?: string; workload?: string; container?: string };
};

/** Stable across restarts, unlike a random id: the agent dedupes on it. */
function signatureId(signature: string): number {
  const digest = createHash("sha256").update(signature).digest();
  return digest.readUInt32BE(0) % 2 ** 31;
}

function base(path: string | undefined): string {
  if (!path) return "";
  const cut = path.lastIndexOf("/");
  return cut === -1 ? path : path.slice(cut + 1);
}

const UNSET_AUID = 4294967295;

function skeleton(ts: string | undefined, signature: string, severity: Severity) {
  return {
    id: randomUUID(),
    ts: ts ?? new Date().toISOString(),
    srcIp: "0.0.0.0",
    srcPort: 0,
    destIp: "0.0.0.0",
    destPort: 0,
    proto: "TCP" as const,
    signature,
    signatureId: signatureId(signature),
    severity,
    tags: [] as string[],
    direction: "to_server" as const,
    bytesToServer: 0,
    bytesToClient: 0,
  };
}

function tetragonEvent(raw: Record<string, unknown>, ts: string | undefined): SecurityEvent | null {
  const process = (raw.process ?? {}) as TetragonProcess;
  const parent = (raw.parent ?? {}) as TetragonProcess;
  const binary = clean(process.binary, 300) ?? "";
  if (!binary && raw.kind !== "process_kprobe") return null;

  const pod = process.pod ?? {};
  const namespace = clean(pod.namespace, 63);
  const name = base(binary);
  const isKprobe = raw.kind === "process_kprobe";
  const fn = clean(raw.function as string, 120);

  // A host process run by a real login session is the desktop attack path; an
  // exec inside a container is one of hundreds a second. Severity reflects that
  // difference and nothing else — what makes an event interesting is the rule
  // that hits it.
  const interactive = !namespace && process.auid !== undefined && process.auid !== UNSET_AUID;
  const severity: Severity = isKprobe ? 3 : interactive ? 3 : 4;

  const signature = isKprobe
    ? `CLUSTER ${fn ?? "kprobe"} by ${name || "unknown"}`
    : `CLUSTER exec ${name || "unknown"}${namespace ? ` in ${namespace}` : " on host"}`;

  const k8s: KubernetesContext = {
    namespace,
    workload: clean(pod.workload, 253),
    container: clean(pod.container, 63),
    kprobe: isKprobe ? fn : undefined,
  };

  return {
    ...skeleton(ts, signature, severity),
    category: isKprobe ? "Suspicious Local Activity" : "Process Execution",
    appProto: undefined,
    source: "tetragon",
    assetId: namespace ? `pod:${namespace}/${clean(pod.name, 253) ?? "?"}` : "host",
    processName: name || undefined,
    processPath: binary || undefined,
    processPid: typeof process.pid === "number" ? process.pid : undefined,
    parentProcess: base(clean(parent.binary, 300) ?? "") || undefined,
    user: process.uid === undefined ? undefined : `uid:${process.uid}`,
    // Arguments are attacker-influenced and already length-capped by the
    // collector; `url` is where the detection engine looks for fetch targets.
    url: clean(process.arguments, 400),
    k8s,
  };
}

type AuditRecord = {
  verb?: string;
  user?: string;
  resource?: string;
  namespace?: string;
  objectName?: string;
  sourceIPs?: string[];
  userAgent?: string;
  decision?: string;
  code?: number;
  requestURI?: string;
};

const WRITE_VERBS = new Set(["create", "update", "patch", "delete", "deletecollection"]);

/** `system:serviceaccount:prod:builder` -> kind and home namespace. */
export function subjectIdentity(user: string | undefined): {
  kind: KubernetesContext["subjectKind"];
  namespace?: string;
} {
  if (!user) return { kind: "anonymous" };
  if (user === "system:anonymous") return { kind: "anonymous" };
  if (user.startsWith("system:node:")) return { kind: "node" };
  if (user.startsWith("system:serviceaccount:")) {
    return { kind: "serviceaccount", namespace: user.split(":")[2] };
  }
  return { kind: "user" };
}

function auditEvent(raw: AuditRecord, ts: string | undefined): SecurityEvent | null {
  const verb = clean(raw.verb, 20) ?? "";
  const resource = clean(raw.resource, 80) ?? "";
  if (!verb || !resource) return null;

  const user = clean(raw.user, 253) ?? "";
  const decision = raw.decision === "forbid" ? "forbid" : "allow";
  const identity = subjectIdentity(user);
  const write = WRITE_VERBS.has(verb);

  // A refused request is a probe; a write to authority is a change. Both beat a
  // routine read, which is left at 4 for the rules to raise.
  const severity: Severity = decision === "forbid" ? 3 : write ? 3 : 4;
  const signature = `K8S ${verb} ${resource}${decision === "forbid" ? " (forbidden)" : ""}`;

  return {
    ...skeleton(ts, signature, severity),
    srcIp: clean(raw.sourceIPs?.[0], 45) ?? "0.0.0.0",
    category: "Cluster Control Plane",
    source: "k3s-audit",
    assetId: raw.namespace ? `ns:${clean(raw.namespace, 63)}` : "cluster",
    user: user || undefined,
    userAgent: clean(raw.userAgent, 120),
    url: clean(raw.requestURI, 200),
    k8s: {
      verb,
      resource,
      namespace: clean(raw.namespace, 63),
      objectName: clean(raw.objectName, 253),
      subject: user || undefined,
      subjectKind: identity.kind,
      subjectNamespace: identity.namespace,
      decision,
      responseCode: typeof raw.code === "number" ? raw.code : undefined,
    },
  };
}

/** One spool line to an event, or null when the line carries no observation. */
export function clusterRecordToEvent(raw: unknown): SecurityEvent | null {
  if (!raw || typeof raw !== "object") return null;
  const line = raw as SpoolRecord;
  const record = line.record;
  if (!record || typeof record !== "object") return null;
  const ts = clean(line.ts, 40);

  if (line._stream === "tetragon") return tetragonEvent(record, ts);
  if (line._stream === "k3s-audit") return auditEvent(record as AuditRecord, ts);
  if (line._stream === "collector") {
    // The collector reporting its own shed load. Worth an event precisely
    // because a flood is one way to bury a single exec.
    const dropped = typeof record.dropped === "number" ? record.dropped : 0;
    if (dropped <= 0) return null;
    const signature = "CLUSTER telemetry shed by the collector rate limit";
    return {
      ...skeleton(ts, signature, 2),
      category: "Sensor Health",
      source: "tetragon",
      assetId: "host",
      url: `dropped=${dropped}`,
    };
  }
  return null;
}

export function startClusterSource(
  path: () => string,
  paused: () => boolean,
  emit: (event: SecurityEvent) => void,
  onError: (message: string) => void,
): () => void {
  return tailJsonl({
    path,
    paused,
    onError,
    label: "cluster-events.jsonl",
    onRecord: (raw) => {
      const event = clusterRecordToEvent(raw);
      if (event) emit(event);
    },
  });
}
