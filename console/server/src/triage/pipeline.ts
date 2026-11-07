import { randomUUID } from "node:crypto";
import type {
  Alert,
  Detection,
  DetectionRun,
  LlmCall,
  SecurityEvent,
  TriageVerdict,
  Verdict,
} from "@aisoc/shared";
import { assetForEvent, recordAlertOnAsset } from "../assets.js";
import { remoteIp, runDetection } from "../detect/engine.js";
import { addTimeline, correlate, recordActionOnIncident } from "../incidents/correlate.js";
import { enrich } from "../intel/enrich.js";
import { blocklistEntry, isAllowlisted } from "../lists.js";
import { onAlertSettled } from "../notify/oncall.js";
import { proposeForAlert } from "../response/actions.js";
import { getSettings } from "../settings.js";
import {
  addAudit,
  addDetectionRun,
  addEvent,
  addNotification,
  getAlert,
  linkDetectionToAlert,
  upsertAlert,
} from "../store.js";
import { createBatcher } from "./batcher.js";
import { markDecision, runTriageCall } from "./llm.js";
import { buildTriageContext, SECOND_TIER_SUFFIX, VERDICT_SYSTEM_PROMPT } from "./prompt.js";

const batcher = createBatcher(VERDICT_SYSTEM_PROMPT + SECOND_TIER_SUFFIX);

/** Suppress repeats of the same (signature, remote IP) so the queue stays readable. */
const DEDUPE_MS = 120_000;
const seen = new Map<string, number>();

/**
 * Drop dedupe keys older than the window. One entry per unique (signature,
 * remote IP) accumulated forever, so a port scan — or any sustained ingest —
 * grew this without bound. Sweeping is O(size) but only runs once a key is
 * actually admitted, which the dedupe window already rate-limits.
 */
function pruneSeen(now: number): void {
  if (seen.size < 5_000) return;
  for (const [key, at] of seen) {
    if (now - at >= DEDUPE_MS) seen.delete(key);
  }
}

/**
 * A 27B on one GPU serialises anyway, so first-tier calls stay capped at two no
 * matter how many jobs are in flight.
 */
const FIRST_TIER_CONCURRENCY = 2;

class Gate {
  #active = 0;
  readonly #queue: (() => void)[] = [];

  constructor(private readonly capacity: number) {}

  async acquire(): Promise<() => void> {
    if (this.#active < this.capacity) {
      this.#active += 1;
    } else {
      await new Promise<void>((resolve) =>
        this.#queue.push(() => {
          this.#active += 1;
          resolve();
        }),
      );
    }
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.#active -= 1;
      this.#queue.shift()?.();
    };
  }
}

const firstTierGate = new Gate(FIRST_TIER_CONCURRENCY);

/**
 * Jobs waiting on a batch hold a slot, so the ceiling has to exceed the batch
 * size or a batch could never fill and would only ever flush on the linger
 * timer. Second-tier calls collapse into one request per batch, so the extra
 * in-flight jobs are cheap.
 */
function maxConcurrent(): number {
  const { batchSize } = getSettings().secondTriage;
  return Math.min(16, Math.max(2, batchSize * 2));
}
/**
 * Triage is slower than ingest can be, so the backlog is capped. Overflow is
 * surfaced as needs-a-human rather than silently dropped or queued forever —
 * an alert nobody looked at is the one failure mode a SOC console must not hide.
 */
const MAX_QUEUE = 15;

type Job = { alert: Alert; run: () => Promise<void> };

let running = 0;
const queue: Job[] = [];

function pump(): void {
  while (running < maxConcurrent() && queue.length > 0) {
    const job = queue.shift()!;
    running += 1;
    void job
      .run()
      .catch((error: unknown) => {
        // A throw must still settle the alert, or it is stranded mid-stage.
        note(
          job.alert,
          `Triage aborted: ${error instanceof Error ? error.message : String(error)}`,
        );
        settle(job.alert, "needs_human");
      })
      .finally(() => {
        running -= 1;
        pump();
      });
  }
}

export function queueBacklog(): { depth: number; capacity: number } {
  return { depth: queue.length, capacity: MAX_QUEUE };
}

function enqueue(alert: Alert, run: () => Promise<void>): void {
  queue.push({ alert, run });
  while (queue.length > MAX_QUEUE) {
    const dropped = queue.shift()!;
    note(
      dropped.alert,
      `Triage capacity exceeded (${MAX_QUEUE} queued) — routed to a human without a model verdict.`,
    );
    dropped.alert.verdict = dropped.alert.verdict ?? "WATCH";
    settle(dropped.alert, "needs_human");
  }
  pump();
}

function note(alert: Alert, body: string, kind: "system" | "comment" = "system"): void {
  alert.notes.push({
    id: randomUUID(),
    at: new Date().toISOString(),
    author: "pipeline",
    kind,
    body,
  });
}

/**
 * Terminal stage for an alert, and the point where everything downstream of a
 * verdict happens: the host's risk moves, the alert joins an incident, response
 * proposes containment, and on-call is paged. Ordering matters — correlation
 * runs before response so an action is filed against the incident it belongs to.
 */
function settle(alert: Alert, stage: "resolved" | "needs_human"): void {
  alert.stage = stage;
  alert.resolvedAt = stage === "resolved" ? new Date().toISOString() : null;
  upsertAlert(alert);

  recordAlertOnAsset(alert);
  correlate(alert);

  void proposeForAlert(alert)
    .then((actions) => {
      for (const action of actions) recordActionOnIncident(action);
    })
    .catch((error: unknown) => {
      note(
        alert,
        `Response proposal failed: ${error instanceof Error ? error.message : String(error)}`,
      );
      upsertAlert(alert);
    });

  onAlertSettled(alert);
}

/**
 * Reject verdicts that would let attacker-controlled text talk us into silence.
 * The detection engine is the floor here: a model cannot dismiss an event that
 * matched a curated indicator or a high-confidence rule, whatever it was told.
 */
function applyFloors(alert: Alert, verdict: TriageVerdict): TriageVerdict {
  if (verdict.verdict !== "IGNORE") return verdict;

  if (alert.event.severity === 1) {
    note(
      alert,
      "Severity-1 IGNORE floored to WATCH — the pipeline never silences a critical alert.",
    );
    return { ...verdict, verdict: "WATCH", confidence: Math.min(verdict.confidence, 0.5) };
  }

  const detection = alert.detection;
  if (detection && detection.band === "malicious") {
    const top = detection.hits[0];
    note(
      alert,
      `IGNORE floored to WATCH — the detection engine scored this ${detection.score}/100${top ? ` on ${top.ruleId} (${top.name})` : ""}, which a model verdict does not override.`,
    );
    return { ...verdict, verdict: "WATCH", confidence: Math.min(verdict.confidence, 0.5) };
  }

  const iocHit = detection?.hits.find((hit) => hit.kind === "ioc" && hit.confidence >= 0.85);
  if (iocHit) {
    note(
      alert,
      `IGNORE floored to WATCH — ${iocHit.value} matched ${iocHit.origin} at ${(iocHit.confidence * 100).toFixed(0)}% confidence.`,
    );
    return { ...verdict, verdict: "WATCH", confidence: Math.min(verdict.confidence, 0.5) };
  }

  return verdict;
}

function firstTierEscalation(alert: Alert, verdict: TriageVerdict): string | null {
  const config = getSettings().firstTriage;
  if (verdict.confidence < config.escalateBelowConfidence) {
    return `confidence ${verdict.confidence.toFixed(2)} below threshold ${config.escalateBelowConfidence.toFixed(2)}`;
  }
  if (config.escalateCategories.includes(alert.event.category)) {
    return `category "${alert.event.category}" is flagged for review`;
  }
  if (alert.event.severity <= config.escalateAtOrBelowSeverity) {
    return `severity ${alert.event.severity} at or above the escalation threshold`;
  }
  if (config.escalateVerdicts.includes(verdict.verdict)) {
    return `verdict ${verdict.verdict} always escalates`;
  }
  return null;
}

function record(alert: Alert, verdict: TriageVerdict, call: LlmCall): void {
  alert.verdict = verdict.verdict;
  alert.confidence = verdict.confidence;
  alert.reason = verdict.reason;
  alert.model = call.model;
  alert.llmCallIds.push(call.id);
}

async function runFirstTriage(alert: Alert): Promise<void> {
  const settings = getSettings();
  alert.stage = "first_triage";
  upsertAlert(alert);

  const releaseFirstTier = await firstTierGate.acquire();
  let call: LlmCall;
  let verdict: TriageVerdict | null;
  try {
    ({ call, verdict } = await runTriageCall({
      stage: "first_triage",
      alertId: alert.id,
      eventId: alert.event.id,
      config: settings.firstTriage,
      systemPrompt: VERDICT_SYSTEM_PROMPT,
      context: buildTriageContext(alert, "first_triage"),
    }));
  } finally {
    releaseFirstTier();
  }
  alert.llmCallIds.push(call.id);

  if (!verdict) {
    // Never fail open: an unreachable or broken first tier escalates.
    alert.escalationReason = `first triage failed (${call.error ?? "unknown error"})`;
    markDecision(call, `Escalated to second triage: ${alert.escalationReason}`);
    note(alert, alert.escalationReason);
    upsertAlert(alert);
    await runSecondTriage(alert);
    return;
  }

  const floored = applyFloors(alert, verdict);
  record(alert, floored, call);

  const escalation = firstTierEscalation(alert, floored);
  if (escalation) {
    alert.escalationReason = escalation;
    markDecision(call, `Escalated to second triage: ${escalation}`);
    upsertAlert(alert);
    await runSecondTriage(alert);
    return;
  }

  if (floored.confidence >= settings.firstTriage.autoCloseConfidence) {
    markDecision(
      call,
      `Auto-closed at first triage: ${floored.verdict} @ ${floored.confidence.toFixed(2)}`,
    );
    settle(alert, "resolved");
    return;
  }

  markDecision(
    call,
    `Held for a human: confidence ${floored.confidence.toFixed(2)} is under the auto-close threshold ${settings.firstTriage.autoCloseConfidence.toFixed(2)}`,
  );
  settle(alert, "needs_human");
}

async function runSecondTriage(alert: Alert): Promise<void> {
  const settings = getSettings();
  alert.stage = "second_triage";
  upsertAlert(alert);

  const context = buildTriageContext(alert, "second_triage");
  let call: LlmCall;
  let verdict: TriageVerdict | null;
  let failure: string | null = null;

  if (settings.secondTriage.batchSize > 1) {
    const outcome = await batcher.submit(alert, context);
    call = outcome.call;
    verdict = outcome.kind === "ok" ? outcome.verdict : null;
    if (outcome.kind === "failed") failure = outcome.error;
    if (outcome.kind === "missing") failure = outcome.reason;
  } else {
    ({ call, verdict } = await runTriageCall({
      stage: "second_triage",
      alertId: alert.id,
      eventId: alert.event.id,
      config: settings.secondTriage,
      systemPrompt: VERDICT_SYSTEM_PROMPT + SECOND_TIER_SUFFIX,
      context,
    }));
    if (!verdict) failure = call.error ?? "unknown error";
  }
  alert.llmCallIds.push(call.id);

  if (!verdict) {
    markDecision(call, `Sent to a human (${alert.id.slice(0, 8)}): second triage failed`);
    note(alert, `Second triage failed (${failure ?? "unknown error"}) — routed to a human.`);
    alert.verdict = alert.verdict ?? "WATCH";
    settle(alert, "needs_human");
    return;
  }

  const floored = applyFloors(alert, verdict);
  record(alert, floored, call);

  // A batched call carries one decision line per alert, so each names its alert.
  const tag = call.batchAlertIds ? `${alert.id.slice(0, 8)}: ` : "";

  if (!settings.secondTriage.autoResolve) {
    markDecision(
      call,
      `${tag}Sent to a human: second triage is configured to always require confirmation`,
    );
    settle(alert, "needs_human");
    return;
  }
  if (floored.confidence < settings.secondTriage.autoResolveConfidence) {
    markDecision(
      call,
      `${tag}Sent to a human: confidence ${floored.confidence.toFixed(2)} is under the auto-resolve threshold ${settings.secondTriage.autoResolveConfidence.toFixed(2)}`,
    );
    settle(alert, "needs_human");
    return;
  }

  markDecision(
    call,
    `${tag}Auto-resolved at second triage: ${floored.verdict} @ ${floored.confidence.toFixed(2)}`,
  );
  settle(alert, "resolved");
}

/**
 * Entry point.
 *
 * The deterministic detection engine runs on every event, before anything else
 * and unconditionally — an event too quiet to open an alert still produces a
 * scored run in the analysis panel, which is what makes the engine auditable
 * rather than a black box that only speaks when it is already sure. Only after
 * that does the event compete for a triage slot, and only then does a model see
 * it.
 */
export function ingestEvent(event: SecurityEvent): void {
  const settings = getSettings();
  const detection = runDetection(event);
  const asset = assetForEvent(event);

  const run: DetectionRun = {
    ...detection,
    id: randomUUID(),
    eventId: event.id,
    alertId: null,
    signature: event.signature,
    remoteIp: remoteIp(event),
    assetId: asset?.id ?? null,
  };
  addDetectionRun(run);

  // Two independent doors into triage: the sensor thought it was severe, or our
  // own engine scored it high enough. Either one is sufficient.
  const bySeverity = event.severity <= settings.ingest.maxTriageSeverity;
  const byScore = detection.score >= settings.detection.alertAtScore;
  if (!bySeverity && !byScore) return;

  const remote = remoteIp(event);
  if (isAllowlisted(remote)) return;

  const key = `${event.signatureId}:${remote}`;
  const last = seen.get(key);
  const now = Date.now();
  if (last && now - last < DEDUPE_MS) return;
  seen.set(key, now);
  pruneSeen(now);

  const alert: Alert = {
    id: randomUUID(),
    origin: "event",
    event,
    stage: "pending",
    verdict: null,
    confidence: 0,
    model: null,
    reason: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    resolvedAt: null,
    escalationReason: null,
    humanOverride: null,
    notes: [],
    llmCallIds: [],
    incidentId: null,
    pageId: null,
    detection,
    enrichment: null,
    assetId: asset?.id ?? null,
    responseIds: [],
  };
  event.alertId = alert.id;
  linkDetectionToAlert(event.id, alert.id);
  upsertAlert(alert);

  if (byScore && !bySeverity) {
    note(
      alert,
      `Opened by the detection engine at score ${detection.score}/100 — the sensor rated this severity ${event.severity}, below the triage threshold.`,
    );
  }
  if (detection.band === "malicious") {
    addNotification({
      kind: "detection",
      level: event.severity === 1 ? "critical" : "warning",
      title: `Malicious: ${detection.hits[0]?.name ?? event.signature}`,
      body: `Score ${detection.score}/100 from ${detection.hits.length} hit${detection.hits.length === 1 ? "" : "s"} on ${remote}.`,
      linkView: "triage",
      linkId: alert.id,
    });
  }

  // Enrichment is best-effort and must never gate triage: the verdict path
  // proceeds whether or not a reputation provider answers.
  void enrich(event)
    .then((enrichment) => {
      if (!enrichment) return;
      const current = getAlert(alert.id);
      if (!current) return;
      current.enrichment = enrichment;
      upsertAlert(current);
    })
    .catch(() => {
      // A provider being down is not a triage failure.
    });

  const blocked = blocklistEntry(remote);
  if (blocked) {
    alert.verdict = "BLOCK";
    alert.confidence = 1;
    alert.model = "blocklist";
    alert.reason = `${remote} is on the operator blocklist: ${blocked.note || "no note"}`;
    note(alert, "Resolved by the operator blocklist before any model was called.");
    settle(alert, "resolved");
    return;
  }

  const autoBlock = settings.escalation.autoBlockPatterns.some((pattern) => {
    try {
      return new RegExp(pattern).test(event.signature);
    } catch {
      return false;
    }
  });

  if (autoBlock) {
    // Deterministic policy tier: curated reputation feeds never reach the LLM,
    // so they stay immune to prompt injection and to model downtime.
    alert.verdict = "BLOCK";
    alert.confidence = 1;
    alert.model = "policy";
    alert.reason = "Signature matches a deterministic auto-block pattern; no model consulted.";
    note(alert, "Resolved by the policy tier before any model was called.");
    settle(alert, "resolved");
    return;
  }

  if (event.severity <= settings.escalation.directToSecondAtOrBelowSeverity) {
    alert.escalationReason = `severity ${event.severity} routes straight to second triage`;
    note(alert, alert.escalationReason);
    upsertAlert(alert);
    enqueue(alert, () => runSecondTriage(alert));
    return;
  }

  enqueue(alert, () => runFirstTriage(alert));
}

/**
 * The only bridge from retained Compass data into alert triage. Its caller
 * supplies a scored aggregate, never the raw flow series, and the alert origin
 * permanently holds every automatic response path for human confirmation.
 */
export function ingestCompassDetection(event: SecurityEvent, detection: Detection): Alert {
  const asset = assetForEvent(event);
  addEvent(event);
  const run: DetectionRun = {
    ...detection,
    id: randomUUID(),
    eventId: event.id,
    alertId: null,
    signature: event.signature,
    remoteIp: remoteIp(event),
    assetId: asset?.id ?? null,
  };
  addDetectionRun(run);

  const alert: Alert = {
    id: randomUUID(),
    origin: "compass_beacon",
    event,
    stage: "pending",
    verdict: null,
    confidence: 0,
    model: null,
    reason: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    resolvedAt: null,
    escalationReason: null,
    humanOverride: null,
    notes: [],
    llmCallIds: [],
    incidentId: null,
    pageId: null,
    detection,
    enrichment: null,
    assetId: asset?.id ?? null,
    responseIds: [],
  };
  event.alertId = alert.id;
  linkDetectionToAlert(event.id, alert.id);
  note(
    alert,
    "Opened by the documented Compass beacon bridge. Raw flows stayed in Compass; only this scored aggregate entered triage. Automatic response is prohibited.",
  );
  upsertAlert(alert);

  void enrich(event)
    .then((enrichment) => {
      if (!enrichment) return;
      const current = getAlert(alert.id);
      if (!current) return;
      current.enrichment = enrichment;
      upsertAlert(current);
    })
    .catch(() => {
      // Reputation providers are best-effort; a local deterministic finding
      // must remain visible when one is unavailable.
    });

  enqueue(alert, () => runFirstTriage(alert));
  return alert;
}

export function applyHumanOverride(
  alertId: string,
  verdict: Verdict,
  by: string,
  body: string,
): Alert | null {
  const alert = getAlert(alertId);
  if (!alert) return null;
  alert.humanOverride = {
    verdict,
    by,
    at: new Date().toISOString(),
    note: body,
    previousVerdict: alert.verdict,
  };
  alert.notes.push({
    id: randomUUID(),
    at: new Date().toISOString(),
    author: by,
    kind: "override",
    body: `${alert.verdict ?? "none"} → ${verdict}. ${body}`.trim(),
  });
  alert.verdict = verdict;
  alert.confidence = 1;
  alert.model = `human:${by}`;
  alert.reason = body || `Overridden by ${by}.`;
  alert.stage = "resolved";
  alert.resolvedAt = new Date().toISOString();
  upsertAlert(alert);

  addAudit(
    by,
    "alert.override",
    alert.event.signature,
    `${alert.humanOverride.previousVerdict ?? "none"} → ${verdict}. ${body}`.trim(),
  );
  if (alert.incidentId) {
    addTimeline(
      alert.incidentId,
      "note",
      `Verdict overridden to ${verdict}`,
      `${by}: ${body || "no note"}`,
      alert.id,
    );
  }
  return alert;
}

export function addComment(alertId: string, author: string, body: string): Alert | null {
  const alert = getAlert(alertId);
  if (!alert) return null;
  alert.notes.push({
    id: randomUUID(),
    at: new Date().toISOString(),
    author,
    kind: "comment",
    body,
  });
  upsertAlert(alert);
  return alert;
}

/** Push a needs-human alert back through second triage, e.g. after a config change. */
export function requeue(alertId: string): boolean {
  const alert = getAlert(alertId);
  if (!alert) return false;
  enqueue(alert, () => runSecondTriage(alert));
  return true;
}
