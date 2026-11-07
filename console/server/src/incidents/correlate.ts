import { randomUUID } from "node:crypto";
import type {
  Alert,
  Incident,
  IncidentStatus,
  ResponseAction,
  Severity,
  TimelineEntry,
  TimelineKind,
} from "@aisoc/shared";
import { dedupeMitre } from "@aisoc/shared";
import { assetForEvent } from "../assets.js";
import { isLocal, remoteIp } from "../detect/engine.js";
import { getSettings } from "../settings.js";
import {
  addAudit,
  addNotification,
  getIncident,
  listIncidents,
  nextIncidentRef,
  upsertAlert,
  upsertIncident,
} from "../store.js";
import { runNarrativeCall } from "../triage/llm.js";
import { INCIDENT_SYSTEM_PROMPT } from "./prompt.js";

/**
 * Alert-to-incident correlation.
 *
 * Grouping is deterministic and evidence-based: a shared scripted behaviour, a
 * shared remote address, a shared host, or a shared file hash inside a time
 * window. The model is asked only to narrate what was already grouped, never to
 * decide what belongs together — an attacker who can write into a hostname
 * should not be able to talk two unrelated incidents into one, or one into two.
 */

type Candidate = { key: string; basis: string };

function candidates(alert: Alert): Candidate[] {
  const { groupBy } = getSettings().incidents;
  const out: Candidate[] = [];
  const event = alert.event;

  for (const dimension of groupBy) {
    if (dimension === "scenario" && event.scenario) {
      out.push({
        key: `scenario:${event.scenario}`,
        basis: `scripted behaviour "${event.scenario}"`,
      });
    }
    if (dimension === "remote_ip") {
      const ip = remoteIp(event);
      if (ip && !isLocal(ip)) out.push({ key: `ip:${ip}`, basis: `remote address ${ip}` });
    }
    if (dimension === "asset") {
      const asset = assetForEvent(event);
      if (asset) out.push({ key: `asset:${asset.id}`, basis: `host ${asset.hostname}` });
    }
    if (dimension === "hash" && event.fileSha256) {
      out.push({
        key: `hash:${event.fileSha256}`,
        basis: `file hash ${event.fileSha256.slice(0, 12)}…`,
      });
    }
    if (dimension === "signature") {
      out.push({
        key: `sig:${event.signatureId}`,
        basis: `signature ${event.signatureId}`,
      });
    }
  }
  return out;
}

function entry(
  kind: TimelineKind,
  title: string,
  detail: string,
  refId: string | null,
): TimelineEntry {
  return { id: randomUUID(), at: new Date().toISOString(), kind, title, detail, refId };
}

export function addTimeline(
  incidentId: string,
  kind: TimelineKind,
  title: string,
  detail: string,
  refId: string | null = null,
): void {
  const incident = getIncident(incidentId);
  if (!incident) return;
  incident.timeline.push(entry(kind, title, detail, refId));
  if (incident.timeline.length > 200) incident.timeline.splice(0, incident.timeline.length - 200);
  upsertIncident(incident);
}

function openIncidentFor(keys: Candidate[]): Incident | undefined {
  const windowMs = getSettings().incidents.correlationWindowMinutes * 60_000;
  const cutoff = Date.now() - windowMs;
  const wanted = new Set(keys.map((candidate) => candidate.key));
  return listIncidents()
    .filter((incident) => incident.status !== "closed")
    .filter((incident) => Date.parse(incident.updatedAt) >= cutoff)
    .filter((incident) => incident.indicators.some((key) => wanted.has(key)))
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))[0];
}

function titleFor(alert: Alert, basis: string): string {
  const top = alert.detection?.hits[0];
  if (top) return `${top.name} — ${basis}`;
  return `${alert.event.signature} — ${basis}`;
}

/** Folds a settled alert into an incident, creating one if nothing matches. */
export function correlate(alert: Alert): Incident | null {
  const settings = getSettings();
  if (!settings.incidents.enabled) return null;
  // Only alerts that stood for something get grouped; a confident IGNORE is noise.
  if (
    alert.verdict === "IGNORE" &&
    (alert.detection?.score ?? 0) < settings.detection.alertAtScore
  ) {
    return null;
  }

  const keys = candidates(alert);
  if (keys.length === 0) return null;

  const asset = assetForEvent(alert.event);
  let incident = openIncidentFor(keys);

  if (!incident) {
    const primary = keys[0]!;
    incident = {
      id: randomUUID(),
      ref: nextIncidentRef(),
      title: titleFor(alert, primary.basis),
      status: "open",
      severity: alert.event.severity,
      correlationKey: primary.key,
      correlationBasis: primary.basis,
      alertIds: [],
      assetIds: [],
      indicators: [],
      mitre: [],
      score: 0,
      assignee: null,
      narrative: null,
      narrativeModel: null,
      suggestedResponse: null,
      timeline: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      closedAt: null,
    };
    incident.timeline.push(
      entry("status", "Incident opened", `Correlated on ${primary.basis}.`, null),
    );
    addNotification({
      kind: "incident",
      level: alert.event.severity === 1 ? "critical" : "warning",
      title: `${incident.ref} opened — ${incident.title}`,
      body: `Correlated on ${primary.basis}.`,
      linkView: "incidents",
      linkId: incident.id,
    });
  }

  if (!incident.alertIds.includes(alert.id)) incident.alertIds.push(alert.id);
  if (asset && !incident.assetIds.includes(asset.id)) incident.assetIds.push(asset.id);
  for (const candidate of keys) {
    if (!incident.indicators.includes(candidate.key)) incident.indicators.push(candidate.key);
  }
  incident.mitre = dedupeMitre([...incident.mitre, ...(alert.detection?.mitre ?? [])]);
  incident.severity = Math.min(incident.severity, alert.event.severity) as Severity;
  incident.score = Math.max(incident.score, alert.detection?.score ?? 0);
  incident.timeline.push(
    entry(
      "alert",
      alert.event.signature,
      `${alert.verdict ?? "pending"} @ ${alert.confidence.toFixed(2)} · detection ${alert.detection?.score ?? 0}/100 (${alert.detection?.band ?? "not run"})`,
      alert.id,
    ),
  );
  for (const hit of alert.detection?.hits.slice(0, 3) ?? []) {
    incident.timeline.push(
      entry("detection", `${hit.ruleId} ${hit.name}`, `${hit.field}=${hit.value}`, alert.id),
    );
  }
  upsertIncident(incident);

  alert.incidentId = incident.id;
  upsertAlert(alert);

  if (!incident.narrative && incident.alertIds.length >= settings.incidents.narrateAtAlertCount) {
    void narrate(incident.id);
  }
  return incident;
}

/**
 * One timeline entry per action per state change. An action is a single thing
 * that moves pending → applied → undone; the timeline should read as that story
 * rather than repeating a line every time something re-proposes the same step.
 */
export function recordActionOnIncident(action: ResponseAction): void {
  if (!action.incidentId) return;
  const incident = getIncident(action.incidentId);
  if (!incident) return;

  const title = `${action.type.replace(/_/g, " ")} ${action.status.replace(/_/g, " ")}`;
  const already = incident.timeline.some(
    (item) => item.kind === "response" && item.refId === action.id && item.title === title,
  );
  if (already) return;

  addTimeline(
    action.incidentId,
    "response",
    title,
    `${action.target} — ${action.reason}${action.guardrail ? ` (${action.guardrail})` : ""}`,
    action.id,
  );
}

/** Asks the second-tier model to write the incident up. Failure is non-fatal. */
export async function narrate(incidentId: string): Promise<void> {
  const incident = getIncident(incidentId);
  if (!incident) return;
  const settings = getSettings();

  const context = {
    incident_ref: incident.ref,
    correlated_on: incident.correlationBasis,
    severity: incident.severity,
    detection_score: incident.score,
    mitre: incident.mitre.map((ref) => `${ref.techniqueId} ${ref.technique} (${ref.tactic})`),
    timeline: incident.timeline.slice(-40).map((item) => ({
      at: item.at,
      kind: item.kind,
      title: item.title,
      detail: item.detail,
    })),
  };

  const { call, narrative } = await runNarrativeCall({
    incidentId,
    config: settings.secondTriage,
    systemPrompt: INCIDENT_SYSTEM_PROMPT,
    context,
  });

  const current = getIncident(incidentId);
  if (!current) return;
  if (!narrative) {
    current.timeline.push(
      entry("llm", "Narrative unavailable", call.error ?? "the model call failed", call.id),
    );
    upsertIncident(current);
    return;
  }

  current.narrative = narrative.narrative;
  current.suggestedResponse = narrative.suggestedResponse;
  current.narrativeModel = call.model;
  current.title = `${narrative.title} (${current.correlationBasis})`;
  current.timeline.push(
    entry("llm", "Narrative written", `${call.model} summarised the incident.`, call.id),
  );
  upsertIncident(current);
}

export function setIncidentStatus(id: string, status: IncidentStatus, by: string): Incident | null {
  const incident = getIncident(id);
  if (!incident) return null;
  const previous = incident.status;
  incident.status = status;
  incident.closedAt = status === "closed" ? new Date().toISOString() : null;
  incident.timeline.push(
    entry("status", `Status ${previous} → ${status}`, `Changed by ${by}.`, null),
  );
  upsertIncident(incident);
  addAudit(by, "incident.status", incident.ref, `${previous} → ${status}`);
  return incident;
}

export function assignIncident(id: string, assignee: string, by: string): Incident | null {
  const incident = getIncident(id);
  if (!incident) return null;
  incident.assignee = assignee || null;
  incident.timeline.push(
    entry("note", "Assignment", `${by} assigned this to ${assignee || "nobody"}.`, null),
  );
  upsertIncident(incident);
  addAudit(by, "incident.assign", incident.ref, `Assigned to ${assignee || "nobody"}`);
  return incident;
}

export function addIncidentNote(id: string, author: string, body: string): Incident | null {
  const incident = getIncident(id);
  if (!incident) return null;
  incident.timeline.push(entry("note", `Note from ${author}`, body, null));
  upsertIncident(incident);
  return incident;
}
