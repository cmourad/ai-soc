import { randomUUID } from "node:crypto";
import type {
  Detection,
  DetectionBand,
  DetectionHit,
  MitreRef,
  SecurityEvent,
  Severity,
} from "@aisoc/shared";
import { dedupeMitre, isLocal, mitre, outboundPayloadBytes, remoteIp } from "@aisoc/shared";
import { isAllowlisted } from "../lists.js";
import { getSettings } from "../settings.js";
import { ENGINE_VERSION, lookupDomain, lookupIoc } from "./feeds.js";
import { RULES } from "./rules.js";

export { ENGINE_VERSION };

/**
 * The deterministic layer. Every event passes through here before anything is
 * sent to a model, so a rule or indicator hit is never contingent on the LLM
 * being reachable, correct, or un-manipulated. The model's job downstream is to
 * explain and contextualise these hits — not to be the only thing that finds
 * them.
 *
 * Scores are additive with diminishing returns rather than a plain sum: three
 * weak corroborating signals should out-rank one weak signal, but should not
 * out-rank a single high-confidence hash match.
 */

export { isLocal, localIp, outboundBytes, outboundPayloadBytes, remoteIp } from "@aisoc/shared";

/** Every hostname-shaped field an indicator could match on. */
function hostnames(event: SecurityEvent): { field: string; value: string }[] {
  const out: { field: string; value: string }[] = [];
  if (event.sni) out.push({ field: "sni", value: event.sni });
  if (event.hostname) out.push({ field: "hostname", value: event.hostname });
  return out;
}

// --- Behavioural state ------------------------------------------------------
//
// Heuristics need memory across events. Each map is keyed by the actor the
// heuristic is about and trimmed on read, so nothing grows without bound.

type Timed = { at: number; value: number };

const portsProbed = new Map<string, Set<number>>();
const portProbeFirstSeen = new Map<string, number>();
const authFailures = new Map<string, number[]>();
const outboundVolume = new Map<string, Timed[]>();
const flowEgressHighWater = new Map<string, Timed>();
const fileWrites = new Map<string, number[]>();

const SCAN_WINDOW_MS = 5 * 60_000;
const STUFFING_WINDOW_MS = 5 * 60_000;
const VOLUME_WINDOW_MS = 10 * 60_000;
const FILE_WINDOW_MS = 60_000;

/**
 * Suricata's byte counters are cumulative for the life of the flow, so every
 * alert on a long-lived connection carries the whole total again. Summing them
 * as they arrive turned one 33 MB download into 429 GB of apparent egress.
 * Only what the flow gained since we last saw it is new volume.
 */
function newEgressBytes(event: SecurityEvent, now: number): number {
  const egress = outboundPayloadBytes(event);
  const ends = [`${event.srcIp}:${event.srcPort}`, `${event.destIp}:${event.destPort}`].sort();
  const key = `${ends[0]}-${ends[1]}`;
  const seen = flowEgressHighWater.get(key);
  flowEgressHighWater.set(key, { at: now, value: egress });
  if (flowEgressHighWater.size > 4_096) {
    const cutoff = now - VOLUME_WINDOW_MS;
    for (const [k, entry] of flowEgressHighWater) {
      if (entry.at < cutoff) flowEgressHighWater.delete(k);
    }
  }
  if (!seen || seen.at < now - VOLUME_WINDOW_MS) return egress;
  return Math.max(0, egress - seen.value);
}

function trim(times: number[], windowMs: number, now: number): number[] {
  const cutoff = now - windowMs;
  while (times.length > 0 && times[0]! < cutoff) times.shift();
  return times;
}

function heuristicHit(
  id: string,
  name: string,
  description: string,
  severity: Severity,
  score: number,
  confidence: number,
  field: string,
  value: string,
  refs: MitreRef[],
): DetectionHit {
  return {
    id: randomUUID(),
    kind: "heuristic",
    ruleId: id,
    name,
    description,
    score,
    severity,
    field,
    value,
    origin: "aisoc behavioural analytics",
    confidence,
    mitre: refs,
  };
}

function runHeuristics(event: SecurityEvent, now: number): DetectionHit[] {
  const hits: DetectionHit[] = [];
  const remote = remoteIp(event);

  // Port scanning: one remote address touching many distinct ports quickly.
  if (!isLocal(remote) && event.direction === "to_server") {
    const first = portProbeFirstSeen.get(remote);
    if (!first || now - first > SCAN_WINDOW_MS) {
      portProbeFirstSeen.set(remote, now);
      portsProbed.set(remote, new Set());
    }
    const ports = portsProbed.get(remote) ?? new Set<number>();
    ports.add(event.destPort);
    portsProbed.set(remote, ports);
    if (ports.size >= 6) {
      hits.push(
        heuristicHit(
          "AISOC-BEH-SCAN",
          "Horizontal port scan",
          `${ports.size} distinct destination ports probed from one address inside ${SCAN_WINDOW_MS / 60_000} minutes.`,
          2,
          Math.min(35, 12 + ports.size * 2),
          0.85,
          "srcIp",
          `${remote} → ${ports.size} ports`,
          mitre("T1046"),
        ),
      );
    }
  }

  // Credential stuffing: repeated authentication attempts from one source.
  const authPorts = [22, 3389, 445, 80, 443];
  if (
    authPorts.includes(event.destPort) &&
    /login|auth|brute|password|credential|ssh/i.test(`${event.signature} ${event.url ?? ""}`)
  ) {
    const times = trim(authFailures.get(remote) ?? [], STUFFING_WINDOW_MS, now);
    times.push(now);
    authFailures.set(remote, times);
    if (times.length >= 8) {
      hits.push(
        heuristicHit(
          "AISOC-BEH-STUFF",
          "Credential stuffing burst",
          `${times.length} authentication attempts from one address in under ${STUFFING_WINDOW_MS / 60_000} minutes.`,
          1,
          Math.min(42, 18 + times.length),
          0.88,
          "srcIp",
          `${remote} · ${times.length} attempts`,
          mitre("T1110.004"),
        ),
      );
    }
  }

  // Exfiltration: cumulative outbound volume to one external destination.
  const egress = newEgressBytes(event, now);
  if (!isLocal(remote) && egress > 0) {
    const entries = outboundVolume.get(remote) ?? [];
    const cutoff = now - VOLUME_WINDOW_MS;
    const kept = entries.filter((entry) => entry.at >= cutoff);
    kept.push({ at: now, value: egress });
    outboundVolume.set(remote, kept);
    const total = kept.reduce((sum, entry) => sum + entry.value, 0);
    if (total > 50_000_000) {
      hits.push(
        heuristicHit(
          "AISOC-BEH-EXFIL",
          "Sustained outbound data volume",
          `${(total / 1_000_000).toFixed(0)} MB pushed to one external address in ${VOLUME_WINDOW_MS / 60_000} minutes.`,
          1,
          Math.min(44, 20 + Math.round(total / 10_000_000)),
          0.8,
          "bytes",
          `${(total / 1_000_000).toFixed(0)} MB → ${remote}`,
          mitre("T1041", "T1048"),
        ),
      );
    }
  }

  // Mass file modification: the signature of an encryptor working through a tree.
  if (event.filePath && event.assetId) {
    const times = trim(fileWrites.get(event.assetId) ?? [], FILE_WINDOW_MS, now);
    times.push(now);
    fileWrites.set(event.assetId, times);
    if (times.length >= 12) {
      hits.push(
        heuristicHit(
          "AISOC-BEH-MASSWRITE",
          "Mass file modification",
          `${times.length} file writes on one host inside a minute — consistent with bulk encryption or wiping.`,
          1,
          Math.min(50, 22 + times.length),
          0.86,
          "assetId",
          `${event.assetId} · ${times.length} writes/min`,
          mitre("T1486"),
        ),
      );
    }
  }

  return hits;
}

function iocHits(event: SecurityEvent): DetectionHit[] {
  const hits: DetectionHit[] = [];
  const add = (entry: ReturnType<typeof lookupIoc>, field: string, value: string): void => {
    if (!entry) return;
    hits.push({
      id: randomUUID(),
      kind: "ioc",
      ruleId: `ioc:${entry.type}:${entry.value}`,
      name: entry.name,
      description: entry.description,
      score: entry.score,
      severity: entry.severity,
      field,
      value,
      origin: entry.origin,
      confidence: entry.confidence,
      mitre: entry.mitre,
    });
  };

  const remote = remoteIp(event);
  add(lookupIoc("ip", remote), remote === event.srcIp ? "srcIp" : "destIp", remote);
  for (const { field, value } of hostnames(event)) add(lookupDomain(value), field, value);
  if (event.fileSha256) add(lookupIoc("hash", event.fileSha256), "fileSha256", event.fileSha256);

  return hits;
}

function ruleHits(event: SecurityEvent): DetectionHit[] {
  const muted = new Set(getSettings().detection.mutedRuleIds);
  const hits: DetectionHit[] = [];
  for (const rule of RULES) {
    if (muted.has(rule.id)) continue;
    const match = rule.match(event);
    if (!match) continue;
    hits.push({
      id: randomUUID(),
      kind: "rule",
      ruleId: rule.id,
      name: rule.name,
      description: rule.description,
      score: rule.score,
      severity: rule.severity,
      field: match.field,
      value: match.value.slice(0, 300),
      origin: rule.origin,
      confidence: rule.confidence,
      mitre: rule.mitre,
    });
  }
  return hits;
}

/**
 * Diminishing-returns aggregation. The strongest hit counts in full; each
 * subsequent hit contributes a shrinking share, so a pile of weak correlations
 * can build a case without ever manufacturing certainty out of noise.
 */
function aggregate(hits: DetectionHit[]): number {
  const weighted = hits.map((hit) => hit.score * hit.confidence).sort((a, b) => b - a);
  let total = 0;
  weighted.forEach((value, index) => {
    total += value / (index + 1);
  });
  return Math.min(100, Math.round(total));
}

export function detectionFromHits(hits: DetectionHit[], startedAt = Date.now()): Detection {
  const score = aggregate(hits);
  return {
    score,
    band: bandFor(score),
    hits: [...hits].sort((a, b) => b.score * b.confidence - a.score * a.confidence),
    mitre: dedupeMitre(hits.flatMap((hit) => hit.mitre)),
    engineVersion: ENGINE_VERSION,
    ranAt: new Date(startedAt).toISOString(),
    durationMs: Math.max(1, Date.now() - startedAt),
  };
}

function bandFor(score: number): DetectionBand {
  const { detection } = getSettings();
  if (score >= detection.maliciousAtScore) return "malicious";
  if (score >= Math.max(10, Math.round(detection.alertAtScore / 2))) return "suspicious";
  return "clean";
}

/** Suricata's own severity is evidence too, but weaker than a first-party hit. */
function signatureHit(event: SecurityEvent): DetectionHit | null {
  if (event.severity > 2) return null;
  return {
    id: randomUUID(),
    kind: "rule",
    ruleId: `suricata:${event.signatureId}`,
    name: event.signature,
    description: `Sensor signature ${event.signatureId} in category "${event.category}".`,
    score: event.severity === 1 ? 30 : 18,
    severity: event.severity,
    field: "signature",
    value: event.signature,
    origin: "suricata ET Open",
    confidence: 0.6,
    mitre: [],
  };
}

export function runDetection(event: SecurityEvent): Detection {
  const startedAt = Date.now();
  const { detection } = getSettings();

  let hits: DetectionHit[] = [];
  if (detection.enabled) {
    if (detection.iocEnabled) hits.push(...iocHits(event));
    if (detection.rulesEnabled) {
      hits.push(...ruleHits(event));
      const signature = signatureHit(event);
      if (signature) hits.push(signature);
    }
    if (detection.heuristicsEnabled) hits.push(...runHeuristics(event, startedAt));
  }

  // An allowlisted indicator suppresses scoring but stays visible, so an
  // operator can always see what would have fired and why it did not.
  const remote = remoteIp(event);
  const allowed = isAllowlisted(remote) || hostnames(event).some((h) => isAllowlisted(h.value));
  if (allowed) {
    hits = hits.map((hit) => ({
      ...hit,
      score: 0,
      description: `${hit.description} (suppressed — indicator is allowlisted)`,
    }));
  }

  return detectionFromHits(hits, startedAt);
}
